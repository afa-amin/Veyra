use rand::rngs::OsRng;
use veyra_core::{decrypt_reader, encrypt_reader, keygen, parse_policy, setup, Attribute, DEFAULT_CHUNK_SIZE};
use std::io::Cursor;

#[test]
fn policy_examples_evaluate() {
    let tree=parse_policy("clearance>=4 AND department=engineering").unwrap();
    let attrs=["clearance>=1","clearance>=2","clearance>=3","clearance>=4","department=engineering"].into_iter().map(String::from).collect();
    assert!(tree.satisfied_by(&attrs));
}

#[test]
fn streaming_round_trip_and_tamper_detection() {
    let (pk,msk)=setup(&[],&mut OsRng);
    let attrs=vec!["clearance>=1".into(),"department=general".into(),"role=member".into()];
    let sk=keygen(&pk,&msk,"recipient",&attrs,&mut OsRng).unwrap();
    let input=vec![42u8; DEFAULT_CHUNK_SIZE+123];
    let mut object=Vec::new();
    encrypt_reader(&pk,"clearance>=1","sample.bin","application/octet-stream",input.len() as u64,Cursor::new(input.clone()),&mut object,DEFAULT_CHUNK_SIZE,&mut OsRng).unwrap();
    let mut output=Vec::new();
    decrypt_reader(&pk,&sk,Cursor::new(object.clone()),&mut output).unwrap();
    assert_eq!(output,input);
    let pos=object.len()/2; object[pos]^=1;
    let mut output=Vec::new(); assert!(decrypt_reader(&pk,&sk,Cursor::new(object),&mut output).is_err());
}
