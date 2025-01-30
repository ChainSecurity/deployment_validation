#[cfg(test)]

mod tests {
    use alloy::primitives::Address;
    use assert_cmd::Command;
    use dvf_libs::dvf::config::DVFConfig;
    use dvf_libs::utils::pretty::ResolvedAddress;
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::thread::sleep;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn test_invalid_bytecode() {
        let config_file = match DVFConfig::test_config_file(None) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };

        const KNOWN_ADDRS: &str = include_str!("../addresses/known.json");

        let known_addrs: HashMap<u64, HashMap<Address, ResolvedAddress>> =
            serde_json::from_str(KNOWN_ADDRS).unwrap();
        for (chain_id, chain_addrs) in &known_addrs {
            let mut keys = chain_addrs.keys();
            let first_address = keys.next().unwrap();
            let last_address = keys.next().unwrap();

            // Create a temporary directory.
            let temp_dir = TempDir::new().expect("Failed to create temp dir");

            // Get the path of the temporary directory.
            let temp_path = temp_dir.path();

            let chain_id_str = format!("{}", chain_id);
            let first_address_str = format!("{:?}", first_address);
            let last_address_str = format!("{:?}", last_address);

            let mut fetch_cmd = Command::cargo_bin("fetch-from-etherscan").unwrap();
            let assert = fetch_cmd
                .args(&[
                    "--config",
                    &config_file.path().to_string_lossy(),
                    "--address",
                    &first_address_str,
                    "--chainid",
                    &chain_id_str,
                    "--project",
                    temp_path.to_str().unwrap(),
                ])
                .assert()
                .success();
            let fetch_out = String::from_utf8_lossy(&assert.get_output().stdout);
            let last_line = fetch_out.lines().last().unwrap();
            let contract_name = last_line.split_whitespace().nth(11).unwrap();
            sleep(Duration::from_millis(250));

            Command::new("sync").assert().success();
            sleep(Duration::from_millis(100));

            let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
            dvf_cmd
                .args(&[
                    "--config",
                    &config_file.path().to_string_lossy(),
                    "bytecode-check",
                    "--address",
                    &last_address_str,
                    "--chainid",
                    &chain_id_str,
                    "--project",
                    temp_path.to_str().unwrap(),
                    "--contractname",
                    &contract_name,
                ])
                .assert()
                .failure();
        }
    }

    #[test]
    fn test_valid_bytecode_for_known_addresses() {
        let config_file = match DVFConfig::test_config_file(None) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };

        const KNOWN_ADDRS: &str = include_str!("../addresses/known.json");

        let known_addrs: HashMap<u64, HashMap<Address, ResolvedAddress>> =
            serde_json::from_str(KNOWN_ADDRS).unwrap();
        let addresses_with_factory =
            vec![Address::from_str("0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f").unwrap()];

        for (chain_id, chain_addrs) in &known_addrs {
            for (address, _) in chain_addrs {
                // Create a temporary directory.
                let temp_dir = TempDir::new().expect("Failed to create temp dir");

                // Get the path of the temporary directory.
                let temp_path = temp_dir.path();

                let chain_id_str = format!("{}", chain_id);
                let address_str = format!("{:?}", address);

                let mut fetch_cmd = Command::cargo_bin("fetch-from-etherscan").unwrap();
                let assert = fetch_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "--address",
                        &address_str,
                        "--chainid",
                        &chain_id_str,
                        "--project",
                        temp_path.to_str().unwrap(),
                    ])
                    .assert()
                    .success();
                let fetch_out = String::from_utf8_lossy(&assert.get_output().stdout);
                let last_line = fetch_out.lines().last().unwrap();
                let contract_name = last_line.split_whitespace().nth(11).unwrap();
                // make sure to not hit the rate limit
                sleep(Duration::from_millis(250));

                Command::new("sync").assert().success();
                sleep(Duration::from_millis(100));

                let factory_mode = addresses_with_factory.contains(&address);

                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                dvf_cmd.args(&[
                    "--config",
                    &config_file.path().to_string_lossy(),
                    "bytecode-check",
                    "--address",
                    &address_str,
                    "--chainid",
                    &chain_id_str,
                    "--project",
                    temp_path.to_str().unwrap(),
                    "--contractname",
                    &contract_name,
                ]);
                if factory_mode {
                    dvf_cmd.arg("--factory");
                }
                let assert = dvf_cmd.assert().success();
                println!("{}", address_str);
                //println!("{}", assert);
                println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));
            }
        }
    }

    #[test]
    fn test_factory_mode_required() {
        let config_file = match DVFConfig::test_config_file(None) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };

        const KNOWN_ADDRS: &str = include_str!("../addresses/known.json");

        let known_addrs: HashMap<u64, HashMap<Address, ResolvedAddress>> =
            serde_json::from_str(KNOWN_ADDRS).unwrap();
        let addresses_with_factory =
            vec![Address::from_str("0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f").unwrap()];

        for (chain_id, chain_addrs) in &known_addrs {
            for (address, _) in chain_addrs {
                if !addresses_with_factory.contains(address) {
                    continue;
                }

                // Create a temporary directory.
                let temp_dir = TempDir::new().expect("Failed to create temp dir");

                // Get the path of the temporary directory.
                let temp_path = temp_dir.path();

                let chain_id_str = format!("{}", chain_id);
                let address_str = format!("{:?}", address);

                let mut fetch_cmd = Command::cargo_bin("fetch-from-etherscan").unwrap();
                let assert = fetch_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "--address",
                        &address_str,
                        "--chainid",
                        &chain_id_str,
                        "--project",
                        temp_path.to_str().unwrap(),
                    ])
                    .assert()
                    .success();
                let fetch_out = String::from_utf8_lossy(&assert.get_output().stdout);
                let last_line = fetch_out.lines().last().unwrap();
                let contract_name = last_line.split_whitespace().nth(11).unwrap();
                sleep(Duration::from_millis(250));

                Command::new("sync").assert().success();
                sleep(Duration::from_millis(100));

                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                dvf_cmd.args(&[
                    "--config",
                    &config_file.path().to_string_lossy(),
                    "bytecode-check",
                    "--address",
                    &address_str,
                    "--chainid",
                    &chain_id_str,
                    "--project",
                    temp_path.to_str().unwrap(),
                    "--contractname",
                    &contract_name,
                ]);
                dvf_cmd.assert().failure();
                //println!("{}", address_str);
                //println!("{}", assert);
                //println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));
            }
        }
    }
}
