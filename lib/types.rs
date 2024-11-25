#[derive(Debug, Default)]
pub struct Immutable {
    pub id: usize,
    pub immutable_starts: Vec<u32>,
    pub length: u32,
    pub name: String,
    pub value: String,
    pub type_string: String,
}

/// Function param.
#[derive(Debug, Clone, PartialEq)]
pub struct ConstructorArg {
    pub name: String,
    pub value: String,
    pub type_string: String,
}

#[derive(Debug)]
pub struct ParsedJason {
    pub compiled_bytecode: String,
    pub immutables: Vec<Immutable>,
}
