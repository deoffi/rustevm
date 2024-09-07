// a memory in machine that you can store and load(set and get) a range of things.
//
use primitive_types::U256;

// addresses are from 0 to 2^256
#[derive(Clone, Debug)]
pub struct Memory {
    data: Vec<u8>,
}

impl Default for Memory {
    fn default() -> Self {
        Self { data: vec![] }
    }
}

impl Memory {
    pub fn load(&self, offset: usize, size: usize) -> Vec<u8> {
        let mut ret = vec![0; size];

        for idx in offset..(offset + size) {
            if let Some(value) = self.data.get(idx) {
                ret[idx - offset] = *value;
            } else {
                ret[idx - offset] = 0;
            }
        }

        ret
    }

    pub fn store(&mut self, offset: usize, data: Vec<u8>) {
        // XXX: not sure if this is the correct behavior?
        //      as in, should this ever be used if EVM is used properly?
        // enlarge self.data
        while self.data.len() < offset + data.len() {
            self.data.push(0);
        }
        // XXX: do you just overwrite?
        for idx in offset..(offset + data.len()) {
            self.data[idx] = data[idx - offset];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default() {
        let m = Memory::default();
        assert_eq!(m.data.len(), 0);
    }

    #[test]
    fn load() {
        let m = Memory::default();
        let data = m.load(
            U256::zero().low_u32() as usize,
            U256::from(32).low_u32() as usize,
        );
        assert_eq!(data, [0; 32]);

        // 0x2a 0x33 ...
    }

    #[test]
    fn store() {
        let mut m = Memory::default();
        m.store(U256::zero().low_u32() as usize, vec![0x00; 32]);
        m.store(U256::from(32).low_u32() as usize, vec![0x01; 32]);
        m.store(U256::from(64).low_u32() as usize, vec![0x02; 32]);
        m.store(U256::from(96).low_u32() as usize, vec![0x03; 32]);

        let output_data = m.load(
            U256::zero().low_u32() as usize,
            U256::from(32).low_u32() as usize,
        );
        assert_eq!(vec![0; 32], output_data);

        let output_data = m.load(
            U256::from(96).low_u32() as usize,
            U256::from(32).low_u32() as usize,
        );
        assert_eq!(vec![3; 32], output_data);

        let output_data = m.load(
            U256::from(128).low_u32() as usize,
            U256::from(32).low_u32() as usize,
        );
        assert_eq!(vec![0; 32], output_data);
    }
}
