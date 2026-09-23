//! Bounded, deterministic Parquet cases from an already admitted and verified dataset.

use super::PreparedDataset;
use bytes::Bytes;
use parquet::{
    basic::Type,
    file::reader::{FileReader, SerializedFileReader},
    record::RowAccessor,
};
use sha2::{Digest, Sha256};

/// One FutureHouse ether0 benchmark row, in physical Parquet row order.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DatasetCase {
    pub id: String,
    pub problem: String,
    pub solution: String,
    pub ideal: String,
    pub problem_type: String,
    pub unformatted: String,
}

/// Safe, typed failure categories for the untrusted artifact boundary.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ParquetCaseError {
    Checksum,
    Limit,
    Malformed,
    Schema,
    Empty,
}

/// Selects the first `limit` cases from verified artifact bytes (maximum eight).
/// The caller must obtain `prepared` through license/suite-admitted `prepare_dataset`.
pub fn decode_parquet_cases(
    prepared: &PreparedDataset,
    bytes: &[u8],
    limit: usize,
) -> Result<Vec<DatasetCase>, ParquetCaseError> {
    const NAMES: [&str; 6] = [
        "id",
        "problem",
        "solution",
        "ideal",
        "problem_type",
        "unformatted",
    ];
    if bytes.len() > 1_048_576 || !(1..=8).contains(&limit) {
        return Err(ParquetCaseError::Limit);
    }
    if format!("sha256:{:x}", Sha256::digest(bytes)) != prepared.checksum() {
        return Err(ParquetCaseError::Checksum);
    }
    let reader = SerializedFileReader::new(Bytes::copy_from_slice(bytes))
        .map_err(|_| ParquetCaseError::Malformed)?;
    let metadata = reader.metadata().file_metadata();
    if !(0..=10_000).contains(&metadata.num_rows()) {
        return Err(ParquetCaseError::Limit);
    }
    let columns = metadata.schema_descr().columns();
    if columns.len() != NAMES.len() {
        return Err(ParquetCaseError::Schema);
    }
    if reader
        .metadata()
        .row_groups()
        .iter()
        .flat_map(|group| group.columns())
        .any(|column| !(0..=16_777_216).contains(&column.uncompressed_size()))
    {
        return Err(ParquetCaseError::Limit);
    }
    let indices: Vec<usize> = NAMES
        .iter()
        .map(|name| {
            let matching: Vec<usize> = columns
                .iter()
                .enumerate()
                .filter(|(_, col)| {
                    col.path().parts().len() == 1
                        && col.name() == *name
                        && col.physical_type() == Type::BYTE_ARRAY
                })
                .map(|(index, _)| index)
                .collect();
            (matching.len() == 1)
                .then(|| matching[0])
                .ok_or(ParquetCaseError::Schema)
        })
        .collect::<Result<_, _>>()?;
    let mut rows = reader
        .get_row_iter(None)
        .map_err(|_| ParquetCaseError::Malformed)?;
    let mut cases = Vec::with_capacity(limit);
    for row in rows.by_ref().take(limit) {
        let row = row.map_err(|_| ParquetCaseError::Malformed)?;
        let text = |index: usize, max: usize| -> Result<String, ParquetCaseError> {
            let value = row
                .get_string(indices[index])
                .map_err(|_| ParquetCaseError::Schema)?;
            if value.is_empty() || value.len() > max {
                return Err(ParquetCaseError::Limit);
            }
            Ok(value.clone())
        };
        let case = DatasetCase {
            id: text(0, 128)?,
            problem: text(1, 16_384)?,
            solution: text(2, 16_384)?,
            ideal: text(3, 16_384)?,
            problem_type: text(4, 16_384)?,
            unformatted: text(5, 16_384)?,
        };
        if cases
            .iter()
            .any(|previous: &DatasetCase| previous.id == case.id)
        {
            return Err(ParquetCaseError::Schema);
        }
        cases.push(case);
    }
    if cases.is_empty() {
        return Err(ParquetCaseError::Empty);
    }
    Ok(cases)
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::{
        data_type::{ByteArray, ByteArrayType},
        file::writer::SerializedFileWriter,
        schema::parser::parse_message_type,
    };
    use std::sync::Arc;

    fn fixture(columns: &[(&str, &[&str])]) -> Vec<u8> {
        fixture_with_id_type(columns, false)
    }

    fn fixture_with_id_type(columns: &[(&str, &[&str])], raw_id: bool) -> Vec<u8> {
        let fields = columns
            .iter()
            .map(|(name, _)| {
                if *name == "id" && raw_id {
                    "REQUIRED BINARY id;".to_owned()
                } else {
                    format!("REQUIRED BINARY {name} (UTF8);")
                }
            })
            .collect::<String>();
        let schema =
            Arc::new(parse_message_type(&format!("message cases {{ {fields} }}")).unwrap());
        let mut bytes = Vec::new();
        {
            let mut writer =
                SerializedFileWriter::new(&mut bytes, schema, Default::default()).unwrap();
            let mut group = writer.next_row_group().unwrap();
            for (_, values) in columns {
                let mut col = group.next_column().unwrap().unwrap();
                let values: Vec<ByteArray> = values.iter().map(|v| ByteArray::from(*v)).collect();
                col.typed::<ByteArrayType>()
                    .write_batch(&values, None, None)
                    .unwrap();
                col.close().unwrap();
            }
            group.close().unwrap();
            writer.close().unwrap();
        }
        bytes
    }

    fn prepared(bytes: &[u8]) -> PreparedDataset {
        use sha2::{Digest, Sha256};
        PreparedDataset {
            checksum: format!("sha256:{:x}", Sha256::digest(bytes)),
            source_identity: super::super::DatasetSourceIdentity::manual("fixture"),
            adapter_version: "1".into(),
            derivation_hash: "fixture".into(),
            from_cache: false,
            case_ids: vec![],
        }
    }

    #[test]
    fn first_rows_have_stable_ids_and_reference_fields() {
        let bytes = fixture(&[
            ("id", &["ether-1", "ether-2"]),
            ("problem", &["question one", "question two"]),
            ("solution", &["answer one", "answer two"]),
            ("ideal", &["ideal one", "ideal two"]),
            ("problem_type", &["type a", "type b"]),
            ("unformatted", &["raw one", "raw two"]),
        ]);
        let cases = decode_parquet_cases(&prepared(&bytes), &bytes, 1).unwrap();
        assert_eq!(cases.len(), 1);
        assert_eq!(cases[0].id, "ether-1");
        assert_eq!(cases[0].problem, "question one");
        assert_eq!(cases[0].solution, "answer one");
        assert_eq!(cases[0].ideal, "ideal one");
        assert_eq!(cases[0].problem_type, "type a");
        assert_eq!(cases[0].unformatted, "raw one");
    }

    #[test]
    fn malformed_schema_and_limits_fail_closed() {
        let columns = [
            ("id", &["ether-1"][..]),
            ("problem", &["question one"][..]),
            ("solution", &["answer one"][..]),
            ("ideal", &["ideal one"][..]),
            ("problem_type", &["type a"][..]),
            ("unformatted", &["raw one"][..]),
        ];
        let bytes = fixture(&columns);
        assert_eq!(
            decode_parquet_cases(&prepared(b"bad"), b"bad", 1),
            Err(ParquetCaseError::Malformed)
        );
        assert_eq!(
            decode_parquet_cases(&prepared(&bytes), &bytes[..bytes.len() - 1], 1),
            Err(ParquetCaseError::Checksum)
        );
        assert_eq!(
            decode_parquet_cases(&prepared(&bytes), &bytes, 0),
            Err(ParquetCaseError::Limit)
        );
        assert_eq!(
            decode_parquet_cases(&prepared(&bytes), &bytes, 9),
            Err(ParquetCaseError::Limit)
        );
        let missing = fixture(&columns[..5]);
        assert_eq!(
            decode_parquet_cases(&prepared(&missing), &missing, 1),
            Err(ParquetCaseError::Schema)
        );
        let wrong_type = fixture_with_id_type(&columns, true);
        assert_eq!(
            decode_parquet_cases(&prepared(&wrong_type), &wrong_type, 1),
            Err(ParquetCaseError::Schema)
        );
        let oversized = fixture(&[
            ("id", &["ether-1"]),
            ("problem", &["question one"]),
            ("solution", &["answer one"]),
            ("ideal", &["ideal one"]),
            ("problem_type", &["type a"]),
            ("unformatted", &[&"x".repeat(16_385)]),
        ]);
        assert_eq!(
            decode_parquet_cases(&prepared(&oversized), &oversized, 1),
            Err(ParquetCaseError::Limit)
        );
        let empty = fixture(&columns.map(|(name, _)| (name, &[][..])));
        assert_eq!(
            decode_parquet_cases(&prepared(&empty), &empty, 1),
            Err(ParquetCaseError::Empty)
        );
        let huge = vec![0; 1_048_577];
        assert_eq!(
            decode_parquet_cases(&prepared(&huge), &huge, 1),
            Err(ParquetCaseError::Limit)
        );
    }
}
