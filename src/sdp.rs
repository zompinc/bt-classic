//! A Service Discovery Protocol server (Core v5.4, Vol 3, Part B).
//!
//! Service records are static data: [`ServiceRecord`]s built from
//! [`DataElement`]s, usually `static`s the application defines. The server
//! answers Service Search, Service Attribute and Service Search Attribute
//! requests, splitting long answers with continuation state. It does no I/O:
//! the runner hands it request PDUs from the SDP L2CAP channel and sends the
//! responses back.

/// SDP's L2CAP PSM.
pub const PSM: u16 = crate::l2cap::psm::SDP;

/// The Bluetooth Base UUID, `00000000-0000-1000-8000-00805F9B34FB`, that
/// 16- and 32-bit UUIDs abbreviate.
pub const BASE_UUID: u128 = 0x00000000_0000_1000_8000_00805f9b34fb;

/// A 16- or 32-bit UUID expanded with the Base UUID.
pub const fn uuid_from_short(short: u32) -> u128 {
    BASE_UUID | ((short as u128) << 96)
}

/// Universal attribute IDs (Assigned Numbers, 5.1).
pub mod attribute {
    pub const SERVICE_RECORD_HANDLE: u16 = 0x0000;
    pub const SERVICE_CLASS_ID_LIST: u16 = 0x0001;
    pub const PROTOCOL_DESCRIPTOR_LIST: u16 = 0x0004;
    pub const BROWSE_GROUP_LIST: u16 = 0x0005;
    pub const BLUETOOTH_PROFILE_DESCRIPTOR_LIST: u16 = 0x0009;
    /// ServiceName at the primary language base (0x0100).
    pub const SERVICE_NAME: u16 = 0x0100;
    /// HSP's Remote Audio Volume Control.
    pub const REMOTE_AUDIO_VOLUME_CONTROL: u16 = 0x0302;
}

/// UUIDs SDP records commonly use.
pub mod uuid {
    pub const L2CAP: u16 = 0x0100;
    pub const RFCOMM: u16 = 0x0003;
    pub const PUBLIC_BROWSE_ROOT: u16 = 0x1002;
    pub const SERIAL_PORT: u16 = 0x1101;
    pub const HEADSET: u16 = 0x1108;
    pub const HEADSET_HS: u16 = 0x1131;
    pub const GENERIC_AUDIO: u16 = 0x1203;
}

/// A data element (Core v5.4, Vol 3, Part B, 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataElement<'a> {
    Nil,
    U8(u8),
    U16(u16),
    U32(u32),
    Uuid16(u16),
    Uuid32(u32),
    Uuid128(u128),
    Text(&'a str),
    Bool(bool),
    Sequence(&'a [DataElement<'a>]),
    Alternative(&'a [DataElement<'a>]),
    Url(&'a str),
}

mod kind {
    pub const NIL: u8 = 0;
    pub const UINT: u8 = 1;
    pub const UUID: u8 = 3;
    pub const TEXT: u8 = 4;
    pub const BOOL: u8 = 5;
    pub const SEQUENCE: u8 = 6;
    pub const ALTERNATIVE: u8 = 7;
    pub const URL: u8 = 8;
}

impl DataElement<'_> {
    /// Encoded length, header included.
    pub fn encoded_len(&self) -> usize {
        match self {
            Self::Nil => 1,
            Self::U8(_) | Self::Bool(_) => 2,
            Self::U16(_) | Self::Uuid16(_) => 3,
            Self::U32(_) | Self::Uuid32(_) => 5,
            Self::Uuid128(_) => 17,
            Self::Text(s) | Self::Url(s) => variable_header_len(s.len()) + s.len(),
            Self::Sequence(items) | Self::Alternative(items) => {
                let body: usize = items.iter().map(DataElement::encoded_len).sum();
                variable_header_len(body) + body
            }
        }
    }

    /// Appends the encoding to `out`.
    pub fn encode(&self, out: &mut Writer<'_>) -> Result<(), Full> {
        match *self {
            Self::Nil => out.byte(kind::NIL << 3),
            Self::U8(v) => out.bytes(&[kind::UINT << 3, v]),
            Self::U16(v) => {
                out.byte((kind::UINT << 3) | 1)?;
                out.bytes(&v.to_be_bytes())
            }
            Self::U32(v) => {
                out.byte((kind::UINT << 3) | 2)?;
                out.bytes(&v.to_be_bytes())
            }
            Self::Uuid16(v) => {
                out.byte((kind::UUID << 3) | 1)?;
                out.bytes(&v.to_be_bytes())
            }
            Self::Uuid32(v) => {
                out.byte((kind::UUID << 3) | 2)?;
                out.bytes(&v.to_be_bytes())
            }
            Self::Uuid128(v) => {
                out.byte((kind::UUID << 3) | 4)?;
                out.bytes(&v.to_be_bytes())
            }
            Self::Bool(v) => out.bytes(&[kind::BOOL << 3, u8::from(v)]),
            Self::Text(s) => {
                variable_header(out, kind::TEXT, s.len())?;
                out.bytes(s.as_bytes())
            }
            Self::Url(s) => {
                variable_header(out, kind::URL, s.len())?;
                out.bytes(s.as_bytes())
            }
            Self::Sequence(items) | Self::Alternative(items) => {
                let kind = if matches!(self, Self::Sequence(_)) {
                    kind::SEQUENCE
                } else {
                    kind::ALTERNATIVE
                };
                let body = items.iter().map(DataElement::encoded_len).sum();
                variable_header(out, kind, body)?;
                items.iter().try_for_each(|item| item.encode(out))
            }
        }
    }

    /// Calls `f` with every UUID in this element, nested ones included,
    /// expanded to 128 bits.
    fn for_each_uuid(&self, f: &mut impl FnMut(u128)) {
        match *self {
            Self::Uuid16(v) => f(uuid_from_short(u32::from(v))),
            Self::Uuid32(v) => f(uuid_from_short(v)),
            Self::Uuid128(v) => f(v),
            Self::Sequence(items) | Self::Alternative(items) => {
                items.iter().for_each(|i| i.for_each_uuid(f))
            }
            _ => {}
        }
    }
}

fn variable_header_len(len: usize) -> usize {
    if len <= 0xff {
        2
    } else if len <= 0xffff {
        3
    } else {
        5
    }
}

fn variable_header(out: &mut Writer<'_>, kind: u8, len: usize) -> Result<(), Full> {
    if len <= 0xff {
        out.bytes(&[(kind << 3) | 5, len as u8])
    } else if len <= 0xffff {
        out.byte((kind << 3) | 6)?;
        out.bytes(&(len as u16).to_be_bytes())
    } else {
        out.byte((kind << 3) | 7)?;
        out.bytes(&(len as u32).to_be_bytes())
    }
}

/// The output buffer is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full;

/// Writes into a byte slice.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> Writer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, len: 0 }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn byte(&mut self, b: u8) -> Result<(), Full> {
        self.bytes(&[b])
    }

    pub fn bytes(&mut self, b: &[u8]) -> Result<(), Full> {
        let end = self.len + b.len();
        if end > self.buf.len() {
            return Err(Full);
        }
        self.buf[self.len..end].copy_from_slice(b);
        self.len = end;
        Ok(())
    }
}

/// One attribute of a record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attribute<'a> {
    pub id: u16,
    pub value: DataElement<'a>,
}

/// A service record. `attributes` must be sorted by ID and must not include
/// the ServiceRecordHandle (0x0000), which comes from `handle`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceRecord<'a> {
    pub handle: u32,
    pub attributes: &'a [Attribute<'a>],
}

impl ServiceRecord<'_> {
    fn contains_uuid(&self, uuid: u128) -> bool {
        let mut found = false;
        for attribute in self.attributes {
            attribute.value.for_each_uuid(&mut |u| found |= u == uuid);
        }
        found
    }

    /// The handle attribute first, then the rest, in ID order.
    fn attributes(&self) -> impl Iterator<Item = (u16, DataElement<'_>)> {
        core::iter::once((
            attribute::SERVICE_RECORD_HANDLE,
            DataElement::U32(self.handle),
        ))
        .chain(self.attributes.iter().map(|a| (a.id, a.value)))
    }

    /// The attribute list for `ids`: a sequence of ID/value pairs.
    fn encode_attributes(&self, ids: &IdList<'_>, out: &mut Writer<'_>) -> Result<(), Full> {
        let selected = || self.attributes().filter(|(id, _)| ids.contains(*id));
        let body: usize = selected().map(|(_, value)| 3 + value.encoded_len()).sum();
        variable_header(out, kind::SEQUENCE, body)?;
        for (id, value) in selected() {
            DataElement::U16(id).encode(out)?;
            value.encode(out)?;
        }
        Ok(())
    }

    fn attributes_len(&self, ids: &IdList<'_>) -> usize {
        let body: usize = self
            .attributes()
            .filter(|(id, _)| ids.contains(*id))
            .map(|(_, value)| 3 + value.encoded_len())
            .sum();
        variable_header_len(body) + body
    }
}

/// The record for an RFCOMM service: class list, L2CAP and RFCOMM channel,
/// public browse group, name. Expands to a `ServiceRecord` built from
/// promoted constants, so it can initialize a `static`.
///
/// ```
/// use bt_classic::rfcomm_service_record;
/// use bt_classic::sdp::{DataElement, ServiceRecord};
///
/// static AA: ServiceRecord<'static> = rfcomm_service_record!(
///     handle: 0x0001_0001,
///     classes: [DataElement::Uuid128(0x4de17a00_52cb_11e6_bdf4_0800200c9a66)],
///     channel: 8,
///     name: "AA Wireless",
/// );
/// ```
#[macro_export]
macro_rules! rfcomm_service_record {
    (
        handle: $handle:expr,
        classes: [$($class:expr),+ $(,)?],
        channel: $channel:expr,
        name: $name:expr
        $(, profiles: [$($profile:expr),+ $(,)?])?
        $(, extra: [$($extra:expr),+ $(,)?])?
        $(,)?
    ) => {
        $crate::sdp::ServiceRecord {
            handle: $handle,
            attributes: &[
                $crate::sdp::Attribute {
                    id: $crate::sdp::attribute::SERVICE_CLASS_ID_LIST,
                    value: $crate::sdp::DataElement::Sequence(&[$($class),+]),
                },
                $crate::sdp::Attribute {
                    id: $crate::sdp::attribute::PROTOCOL_DESCRIPTOR_LIST,
                    value: $crate::sdp::DataElement::Sequence(&[
                        $crate::sdp::DataElement::Sequence(&[$crate::sdp::DataElement::Uuid16(
                            $crate::sdp::uuid::L2CAP,
                        )]),
                        $crate::sdp::DataElement::Sequence(&[
                            $crate::sdp::DataElement::Uuid16($crate::sdp::uuid::RFCOMM),
                            $crate::sdp::DataElement::U8($channel),
                        ]),
                    ]),
                },
                $crate::sdp::Attribute {
                    id: $crate::sdp::attribute::BROWSE_GROUP_LIST,
                    value: $crate::sdp::DataElement::Sequence(&[$crate::sdp::DataElement::Uuid16(
                        $crate::sdp::uuid::PUBLIC_BROWSE_ROOT,
                    )]),
                },
                $(
                    $crate::sdp::Attribute {
                        id: $crate::sdp::attribute::BLUETOOTH_PROFILE_DESCRIPTOR_LIST,
                        value: $crate::sdp::DataElement::Sequence(&[$($profile),+]),
                    },
                )?
                $crate::sdp::Attribute {
                    id: $crate::sdp::attribute::SERVICE_NAME,
                    value: $crate::sdp::DataElement::Text($name),
                },
                $($($extra,)+)?
            ],
        }
    };
}

mod pdu {
    pub const ERROR_RESPONSE: u8 = 0x01;
    pub const SERVICE_SEARCH_REQUEST: u8 = 0x02;
    pub const SERVICE_SEARCH_RESPONSE: u8 = 0x03;
    pub const SERVICE_ATTRIBUTE_REQUEST: u8 = 0x04;
    pub const SERVICE_ATTRIBUTE_RESPONSE: u8 = 0x05;
    pub const SERVICE_SEARCH_ATTRIBUTE_REQUEST: u8 = 0x06;
    pub const SERVICE_SEARCH_ATTRIBUTE_RESPONSE: u8 = 0x07;
}

/// SDP error codes.
pub mod error {
    pub const INVALID_RECORD_HANDLE: u16 = 0x0002;
    pub const INVALID_SYNTAX: u16 = 0x0003;
    pub const INVALID_PDU_SIZE: u16 = 0x0004;
    pub const INVALID_CONTINUATION_STATE: u16 = 0x0005;
}

/// The most UUIDs a search pattern may hold.
const MAX_PATTERN: usize = 12;
/// The longest full response body the server builds; longer ones are cut.
pub const MAX_BODY: usize = 1024;
/// The longest request kept to validate continuation requests.
const MAX_REQUEST: usize = 64;

/// One data element in a request: its type, the size index, and the bytes
/// of its value.
fn parse_element(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&header, rest) = data.split_first()?;
    let (kind, size) = (header >> 3, header & 7);
    let (len, rest) = match size {
        0 if kind == kind::NIL => (0, rest),
        0 => (1, rest),
        1 => (2, rest),
        2 => (4, rest),
        3 => (8, rest),
        4 => (16, rest),
        5 => (usize::from(*rest.first()?), &rest[1..]),
        6 => (
            usize::from(u16::from_be_bytes(rest.get(..2)?.try_into().ok()?)),
            &rest[2..],
        ),
        _ => (
            u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize,
            rest.get(4..)?,
        ),
    };
    let value = rest.get(..len)?;
    Some((kind, value, &rest[len..]))
}

/// A sequence's contents, from the front of `data`.
fn parse_sequence(data: &[u8]) -> Option<(&[u8], &[u8])> {
    match parse_element(data)? {
        (kind::SEQUENCE, items, rest) => Some((items, rest)),
        _ => None,
    }
}

fn parse_uuid(kind: u8, value: &[u8]) -> Option<u128> {
    if kind != kind::UUID {
        return None;
    }
    match value.len() {
        2 => Some(uuid_from_short(u32::from(u16::from_be_bytes(
            value.try_into().ok()?,
        )))),
        4 => Some(uuid_from_short(u32::from_be_bytes(value.try_into().ok()?))),
        16 => Some(u128::from_be_bytes(value.try_into().ok()?)),
        _ => None,
    }
}

/// An AttributeIDList: 16-bit IDs and 32-bit ranges, kept as raw elements.
struct IdList<'a>(&'a [u8]);

impl IdList<'_> {
    fn parse(items: &[u8]) -> Option<IdList<'_>> {
        let mut rest = items;
        while !rest.is_empty() {
            let (kind, value, next) = parse_element(rest)?;
            if kind != kind::UINT || !(value.len() == 2 || value.len() == 4) {
                return None;
            }
            rest = next;
        }
        Some(IdList(items))
    }

    fn contains(&self, id: u16) -> bool {
        let mut rest = self.0;
        while let Some((_, value, next)) = parse_element(rest) {
            let hit = match value.len() {
                2 => u16::from_be_bytes([value[0], value[1]]) == id,
                4 => {
                    let start = u16::from_be_bytes([value[0], value[1]]);
                    let end = u16::from_be_bytes([value[2], value[3]]);
                    (start..=end).contains(&id)
                }
                _ => false,
            };
            if hit {
                return true;
            }
            rest = next;
        }
        false
    }
}

/// The SDP server. See the [module docs](self).
pub struct SdpServer<'r> {
    records: &'r [ServiceRecord<'r>],
    /// The last full response body, for continuation requests.
    body: [u8; MAX_BODY],
    body_len: usize,
    /// The request it answers, without its continuation state.
    request: [u8; MAX_REQUEST],
    request_len: usize,
}

impl<'r> SdpServer<'r> {
    /// A server for `records`.
    pub const fn new(records: &'r [ServiceRecord<'r>]) -> Self {
        Self {
            records,
            body: [0; MAX_BODY],
            body_len: 0,
            request: [0; MAX_REQUEST],
            request_len: 0,
        }
    }

    /// The records served.
    pub fn records(&self) -> &'r [ServiceRecord<'r>] {
        self.records
    }

    /// Answers one request PDU into `response`, for a channel whose peer
    /// accepts `mtu` bytes. Returns the response length.
    pub fn handle(&mut self, request: &[u8], mtu: u16, response: &mut [u8]) -> usize {
        let mut out = Writer::new(response);
        let (Some(&id), Some(tid)) = (request.first(), request.get(1..3)) else {
            return 0; // not even a header: nothing to answer
        };
        let transaction = [tid[0], tid[1]];
        let params_len = request
            .get(3..5)
            .map(|b| usize::from(u16::from_be_bytes([b[0], b[1]])));
        let result = match params_len {
            Some(len) if request.len() == 5 + len => {
                self.dispatch(id, &request[5..], mtu, &transaction, &mut out)
            }
            _ => Err(error::INVALID_PDU_SIZE),
        };
        match result {
            Ok(()) => out.len(),
            Err(code) => {
                let mut out = Writer::new(out.buf);
                let _ = out.bytes(&[pdu::ERROR_RESPONSE, transaction[0], transaction[1], 0, 2]);
                let _ = out.bytes(&code.to_be_bytes());
                out.len()
            }
        }
    }

    fn dispatch(
        &mut self,
        id: u8,
        params: &[u8],
        mtu: u16,
        transaction: &[u8; 2],
        out: &mut Writer<'_>,
    ) -> Result<(), u16> {
        match id {
            pdu::SERVICE_SEARCH_REQUEST => self.service_search(params, mtu, transaction, out),
            pdu::SERVICE_ATTRIBUTE_REQUEST => self.service_attribute(params, mtu, transaction, out),
            pdu::SERVICE_SEARCH_ATTRIBUTE_REQUEST => {
                self.service_search_attribute(params, mtu, transaction, out)
            }
            _ => Err(error::INVALID_SYNTAX),
        }
    }

    /// The records matching a ServiceSearchPattern at the front of `params`,
    /// and what follows it.
    fn search<'p>(
        &self,
        params: &'p [u8],
    ) -> Result<([Option<&'r ServiceRecord<'r>>; 8], &'p [u8]), u16> {
        let (items, rest) = parse_sequence(params).ok_or(error::INVALID_SYNTAX)?;
        let mut pattern = [0u128; MAX_PATTERN];
        let mut count = 0;
        let mut items = items;
        while !items.is_empty() {
            let (kind, value, next) = parse_element(items).ok_or(error::INVALID_SYNTAX)?;
            let uuid = parse_uuid(kind, value).ok_or(error::INVALID_SYNTAX)?;
            if count == MAX_PATTERN {
                return Err(error::INVALID_SYNTAX);
            }
            pattern[count] = uuid;
            count += 1;
            items = next;
        }
        if count == 0 {
            return Err(error::INVALID_SYNTAX);
        }
        let mut matches = [None; 8];
        let mut found = 0;
        for record in self.records {
            if found < matches.len() && pattern[..count].iter().all(|&u| record.contains_uuid(u)) {
                matches[found] = Some(record);
                found += 1;
            }
        }
        Ok((matches, rest))
    }

    /// The continuation state that ends every request: `rest` must be
    /// exactly its length byte and that many bytes. Ours are 2-byte offsets.
    fn continuation(rest: &[u8]) -> Result<Option<usize>, u16> {
        let (&len, state) = rest.split_first().ok_or(error::INVALID_SYNTAX)?;
        if state.len() != usize::from(len) {
            return Err(error::INVALID_SYNTAX);
        }
        match state {
            [] => Ok(None),
            [hi, lo] => Ok(Some(usize::from(u16::from_be_bytes([*hi, *lo])))),
            _ => Err(error::INVALID_CONTINUATION_STATE),
        }
    }

    fn u16_at(data: &[u8], at: usize) -> Result<usize, u16> {
        let b = data.get(at..at + 2).ok_or(error::INVALID_SYNTAX)?;
        Ok(usize::from(u16::from_be_bytes([b[0], b[1]])))
    }

    fn service_search(
        &mut self,
        params: &[u8],
        mtu: u16,
        transaction: &[u8; 2],
        out: &mut Writer<'_>,
    ) -> Result<(), u16> {
        let (matches, rest) = self.search(params)?;
        let max = Self::u16_at(rest, 0)?;
        let offset = Self::continuation(&rest[2..])?;
        let handles: [u32; 8] = core::array::from_fn(|i| matches[i].map_or(0, |r| r.handle));
        let total = matches.iter().flatten().count().min(max);

        // Each handle is 4 bytes; leave room for header, counts and state.
        let room = (usize::from(mtu).saturating_sub(5 + 4 + 3) / 4).max(1);
        let start = offset.unwrap_or(0);
        if start > total {
            return Err(error::INVALID_CONTINUATION_STATE);
        }
        let current = (total - start).min(room);
        let next = start + current;

        let params_len = 4 + 4 * current + if next < total { 3 } else { 1 };
        let w = |r: Result<(), Full>| r.map_err(|_| error::INVALID_PDU_SIZE);
        w(out.bytes(&[pdu::SERVICE_SEARCH_RESPONSE, transaction[0], transaction[1]]))?;
        w(out.bytes(&(params_len as u16).to_be_bytes()))?;
        w(out.bytes(&(total as u16).to_be_bytes()))?;
        w(out.bytes(&(current as u16).to_be_bytes()))?;
        for handle in &handles[start..next] {
            w(out.bytes(&handle.to_be_bytes()))?;
        }
        if next < total {
            w(out.bytes(&[2]))?;
            w(out.bytes(&(next as u16).to_be_bytes()))
        } else {
            w(out.byte(0))
        }
    }

    fn service_attribute(
        &mut self,
        params: &[u8],
        mtu: u16,
        transaction: &[u8; 2],
        out: &mut Writer<'_>,
    ) -> Result<(), u16> {
        let handle = params.get(..4).ok_or(error::INVALID_SYNTAX)?;
        let handle = u32::from_be_bytes([handle[0], handle[1], handle[2], handle[3]]);
        let max = Self::u16_at(params, 4)?;
        let (items, rest) = parse_sequence(&params[6..]).ok_or(error::INVALID_SYNTAX)?;
        let offset = Self::continuation(rest)?;
        let request = &params[..params.len() - rest.len()];
        if offset.is_none() {
            let ids = IdList::parse(items).ok_or(error::INVALID_SYNTAX)?;
            let record = self
                .records
                .iter()
                .find(|r| r.handle == handle)
                .ok_or(error::INVALID_RECORD_HANDLE)?;
            let mut body = Writer::new(&mut self.body);
            record
                .encode_attributes(&ids, &mut body)
                .map_err(|_| error::INVALID_PDU_SIZE)?;
            self.body_len = body.len();
            self.remember(request);
        }
        self.respond_chunk(
            pdu::SERVICE_ATTRIBUTE_RESPONSE,
            request,
            offset,
            max,
            mtu,
            transaction,
            out,
        )
    }

    fn service_search_attribute(
        &mut self,
        params: &[u8],
        mtu: u16,
        transaction: &[u8; 2],
        out: &mut Writer<'_>,
    ) -> Result<(), u16> {
        let (matches, rest) = self.search(params)?;
        let max = Self::u16_at(rest, 0)?;
        let (items, rest) = parse_sequence(&rest[2..]).ok_or(error::INVALID_SYNTAX)?;
        let offset = Self::continuation(rest)?;
        let request = &params[..params.len() - rest.len()];
        if offset.is_none() {
            let ids = IdList::parse(items).ok_or(error::INVALID_SYNTAX)?;
            let records = matches.iter().flatten();
            let body_len: usize = records.clone().map(|r| r.attributes_len(&ids)).sum();
            let mut body = Writer::new(&mut self.body);
            variable_header(&mut body, kind::SEQUENCE, body_len)
                .map_err(|_| error::INVALID_PDU_SIZE)?;
            for record in records {
                record
                    .encode_attributes(&ids, &mut body)
                    .map_err(|_| error::INVALID_PDU_SIZE)?;
            }
            self.body_len = body.len();
            self.remember(request);
        }
        self.respond_chunk(
            pdu::SERVICE_SEARCH_ATTRIBUTE_RESPONSE,
            request,
            offset,
            max,
            mtu,
            transaction,
            out,
        )
    }

    fn remember(&mut self, request: &[u8]) {
        let len = request.len().min(MAX_REQUEST);
        self.request[..len].copy_from_slice(&request[..len]);
        self.request_len = len;
    }

    /// Sends the cached body from `offset`, at most `max` bytes and what
    /// fits the MTU, with continuation state if more remains.
    #[allow(clippy::too_many_arguments)]
    fn respond_chunk(
        &self,
        id: u8,
        request: &[u8],
        offset: Option<usize>,
        max: usize,
        mtu: u16,
        transaction: &[u8; 2],
        out: &mut Writer<'_>,
    ) -> Result<(), u16> {
        let start = offset.unwrap_or(0);
        if offset.is_some() {
            let same = request.len().min(MAX_REQUEST) == self.request_len
                && request[..self.request_len] == self.request[..self.request_len];
            if !same || start >= self.body_len {
                return Err(error::INVALID_CONTINUATION_STATE);
            }
        }
        // Header 5, byte count 2, continuation state up to 3.
        let room = usize::from(mtu).saturating_sub(5 + 2 + 3).min(max).max(1);
        let chunk = (self.body_len - start).min(room);
        let next = start + chunk;
        let more = next < self.body_len;

        let params_len = 2 + chunk + if more { 3 } else { 1 };
        let w = |r: Result<(), Full>| r.map_err(|_| error::INVALID_PDU_SIZE);
        w(out.bytes(&[id, transaction[0], transaction[1]]))?;
        w(out.bytes(&(params_len as u16).to_be_bytes()))?;
        w(out.bytes(&(chunk as u16).to_be_bytes()))?;
        w(out.bytes(&self.body[start..next]))?;
        if more {
            w(out.bytes(&[2]))?;
            w(out.bytes(&(next as u16).to_be_bytes()))
        } else {
            w(out.byte(0))
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec::Vec;

    const AA_UUID: u128 = 0x4de17a00_52cb_11e6_bdf4_0800200c9a66;

    static AA: ServiceRecord<'static> = rfcomm_service_record!(
        handle: 0x0001_0001,
        classes: [DataElement::Uuid128(AA_UUID)],
        channel: 8,
        name: "AA Wireless",
    );

    static HSP: ServiceRecord<'static> = rfcomm_service_record!(
        handle: 0x0001_0002,
        classes: [DataElement::Uuid16(uuid::HEADSET), DataElement::Uuid16(uuid::GENERIC_AUDIO)],
        channel: 6,
        name: "Headset",
        profiles: [DataElement::Sequence(&[DataElement::Uuid16(uuid::HEADSET), DataElement::U16(0x0102)])],
        extra: [Attribute { id: attribute::REMOTE_AUDIO_VOLUME_CONTROL, value: DataElement::Bool(false) }],
    );

    static RECORDS: [ServiceRecord<'static>; 2] = [AA, HSP];

    fn encode(element: &DataElement<'_>) -> Vec<u8> {
        let mut buf = [0u8; 512];
        let mut out = Writer::new(&mut buf);
        element.encode(&mut out).unwrap();
        let len = out.len();
        assert_eq!(len, element.encoded_len());
        buf[..len].to_vec()
    }

    #[test]
    fn data_element_encodings() {
        assert_eq!(encode(&DataElement::Nil), [0x00]);
        assert_eq!(encode(&DataElement::U8(8)), [0x08, 0x08]);
        assert_eq!(encode(&DataElement::U16(0x0102)), [0x09, 0x01, 0x02]);
        assert_eq!(encode(&DataElement::U32(0x00010001)), [0x0a, 0, 1, 0, 1]);
        assert_eq!(encode(&DataElement::Uuid16(0x1108)), [0x19, 0x11, 0x08]);
        assert_eq!(encode(&DataElement::Bool(true)), [0x28, 0x01]);
        assert_eq!(encode(&DataElement::Text("hi")), [0x25, 0x02, b'h', b'i']);
        let mut uuid = std::vec![0x1c];
        uuid.extend_from_slice(&AA_UUID.to_be_bytes());
        assert_eq!(encode(&DataElement::Uuid128(AA_UUID)), uuid);
        // L2CAP + RFCOMM channel 8, as every RFCOMM record carries it.
        let protocols = DataElement::Sequence(&[
            DataElement::Sequence(&[DataElement::Uuid16(uuid::L2CAP)]),
            DataElement::Sequence(&[DataElement::Uuid16(uuid::RFCOMM), DataElement::U8(8)]),
        ]);
        assert_eq!(
            encode(&protocols),
            [
                0x35, 0x0c, 0x35, 0x03, 0x19, 0x01, 0x00, 0x35, 0x05, 0x19, 0x00, 0x03, 0x08, 0x08
            ]
        );
        let long = "x".repeat(300);
        assert_eq!(&encode(&DataElement::Text(&long))[..3], &[0x26, 0x01, 0x2c]);
    }

    fn request(id: u8, params: &[u8]) -> Vec<u8> {
        let mut out = std::vec![id, 0x12, 0x34];
        out.extend_from_slice(&(params.len() as u16).to_be_bytes());
        out.extend_from_slice(params);
        out
    }

    fn ask(server: &mut SdpServer<'_>, id: u8, params: &[u8], mtu: u16) -> Vec<u8> {
        let mut buf = [0u8; 1024];
        let len = server.handle(&request(id, params), mtu, &mut buf);
        buf[..len].to_vec()
    }

    #[test]
    fn service_search_by_16_and_128_bit_uuids() {
        let mut server = SdpServer::new(&RECORDS);
        // Pattern: RFCOMM (in both records).
        let out = ask(
            &mut server,
            0x02,
            &[0x35, 0x03, 0x19, 0x00, 0x03, 0x00, 0x10, 0x00],
            672,
        );
        assert_eq!(
            out,
            [
                0x03, 0x12, 0x34, 0x00, 0x0d, 0, 2, 0, 2, 0, 1, 0, 1, 0, 1, 0, 2, 0x00
            ]
        );

        // Pattern: the AA UUID, given as 128 bits.
        let mut params = std::vec![0x35, 0x11, 0x1c];
        params.extend_from_slice(&AA_UUID.to_be_bytes());
        params.extend_from_slice(&[0x00, 0x10, 0x00]);
        let out = ask(&mut server, 0x02, &params, 672);
        assert_eq!(&out[5..13], &[0, 1, 0, 1, 0, 1, 0, 1]);

        // The Headset UUID as a 128-bit UUID matches its 16-bit form.
        let mut params = std::vec![0x35, 0x11, 0x1c];
        params.extend_from_slice(&uuid_from_short(0x1108).to_be_bytes());
        params.extend_from_slice(&[0x00, 0x10, 0x00]);
        let out = ask(&mut server, 0x02, &params, 672);
        assert_eq!(&out[9..13], &[0, 1, 0, 2]);
    }

    #[test]
    fn service_attribute_returns_the_rfcomm_channel() {
        let mut server = SdpServer::new(&RECORDS);
        // Handle 0x00010001, max 0xffff bytes, attribute 0x0004 only.
        let params = [0, 1, 0, 1, 0xff, 0xff, 0x35, 0x03, 0x09, 0x00, 0x04, 0x00];
        let out = ask(&mut server, 0x04, &params, 672);
        assert_eq!(out[0], 0x05);
        let list = &out[7..out.len() - 1];
        assert_eq!(
            list,
            [
                0x35, 0x11, 0x09, 0x00, 0x04, 0x35, 0x0c, 0x35, 0x03, 0x19, 0x01, 0x00, 0x35, 0x05,
                0x19, 0x00, 0x03, 0x08, 0x08
            ]
        );
        assert_eq!(*out.last().unwrap(), 0);

        // An unknown handle is an error.
        let params = [0, 9, 0, 9, 0xff, 0xff, 0x35, 0x03, 0x09, 0x00, 0x04, 0x00];
        assert_eq!(
            ask(&mut server, 0x04, &params, 672),
            [0x01, 0x12, 0x34, 0, 2, 0, 2]
        );
    }

    /// Collects a ServiceSearchAttribute answer over as many continuation
    /// rounds as it takes.
    fn search_attribute_all(
        server: &mut SdpServer<'_>,
        pattern: &[u8],
        mtu: u16,
        max: u16,
    ) -> (Vec<u8>, usize) {
        let mut body = Vec::new();
        let mut state = std::vec![0u8];
        let mut rounds = 0;
        loop {
            let mut params = pattern.to_vec();
            params.extend_from_slice(&max.to_be_bytes());
            params.extend_from_slice(&[0x35, 0x05, 0x0a, 0x00, 0x00, 0xff, 0xff]); // all attributes
            params.extend_from_slice(&state);
            let out = ask(server, 0x06, &params, mtu);
            assert_eq!(out[0], 0x07, "error response {out:?}");
            assert!(out.len() <= usize::from(mtu));
            let count = usize::from(u16::from_be_bytes([out[5], out[6]]));
            body.extend_from_slice(&out[7..7 + count]);
            state = out[7 + count..].to_vec();
            rounds += 1;
            if state == [0] {
                return (body, rounds);
            }
        }
    }

    #[test]
    fn continuation_reassembles_to_the_same_answer() {
        let pattern = [0x35, 0x03, 0x19, 0x00, 0x03]; // RFCOMM
        let mut server = SdpServer::new(&RECORDS);
        let (whole, rounds) = search_attribute_all(&mut server, &pattern, 672, 0xffff);
        assert_eq!(rounds, 1);
        let (pieces, rounds) = search_attribute_all(&mut server, &pattern, 48, 0xffff);
        assert!(rounds > 1);
        assert_eq!(pieces, whole);
        let (small, _) = search_attribute_all(&mut server, &pattern, 672, 7);
        assert_eq!(small, whole);

        // The whole answer is a sequence of the two records' attribute lists.
        let (items, rest) = parse_sequence(&whole).unwrap();
        assert!(rest.is_empty());
        let (first, items) = parse_sequence(items).unwrap();
        let (second, items) = parse_sequence(items).unwrap();
        assert!(items.is_empty());
        // The AA record starts with its handle, then the class list.
        assert_eq!(&first[..8], &[0x09, 0x00, 0x00, 0x0a, 0, 1, 0, 1]);
        assert_eq!(&second[..8], &[0x09, 0x00, 0x00, 0x0a, 0, 1, 0, 2]);
    }

    #[test]
    fn bad_requests_get_errors() {
        let mut server = SdpServer::new(&RECORDS);
        // Parameter length that does not match.
        let mut bad = request(0x02, &[0x35, 0x03, 0x19, 0x00, 0x03, 0x00, 0x10, 0x00]);
        bad[4] += 1;
        let mut buf = [0u8; 64];
        let len = server.handle(&bad, 672, &mut buf);
        assert_eq!(&buf[..len], &[0x01, 0x12, 0x34, 0, 2, 0, 4]);
        // An unknown PDU.
        assert_eq!(
            ask(&mut server, 0x42, &[0x00], 672),
            [0x01, 0x12, 0x34, 0, 2, 0, 3]
        );
        // A continuation state that was never issued.
        let params = [
            0x35, 0x03, 0x19, 0x00, 0x03, 0xff, 0xff, 0x35, 0x05, 0x0a, 0, 0, 0xff, 0xff, 2, 0x03,
            0x00,
        ];
        assert_eq!(
            ask(&mut server, 0x06, &params, 672),
            [0x01, 0x12, 0x34, 0, 2, 0, 5]
        );
    }
}
