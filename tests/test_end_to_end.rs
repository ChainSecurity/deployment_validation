#[cfg(test)]

mod tests {
    use alloy_node_bindings::{Anvil, AnvilInstance};
    use assert_cmd::Command;
    use dvf_libs::dvf::config::DVFConfig;
    use dvf_libs::dvf::parse::CompleteDVF;
    use std::fs::metadata;
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::io::{self, Write};
    use std::io::{BufRead, BufReader};
    use std::panic;
    use std::path::Path;
    use std::process::{Child, Command as SimpleCommand, Stdio};
    use std::thread::sleep;
    use std::time::Duration;
    use tempfile::NamedTempFile;

    #[derive(PartialEq, Clone)]
    enum LocalClientType {
        Anvil,
        Geth,
    }

    impl LocalClientType {
        fn iterator() -> impl Iterator<Item = LocalClientType> {
            [LocalClientType::Anvil, LocalClientType::Geth]
                .iter()
                .cloned()
        }

        fn to_string(&self) -> String {
            match self {
                LocalClientType::Anvil => String::from("Anvil"),
                LocalClientType::Geth => String::from("Geth"),
            }
        }
    }

    enum LocalClient {
        Anvil(AnvilInstance),
        Geth(Child),
    }

    impl Drop for LocalClient {
        fn drop(&mut self) {
            match self {
                // This does nothing but it is fine because we will drop
                // it implicitly. Should be refactored at some point.
                #[allow(dropping_references)]
                LocalClient::Anvil(a) => drop(a),
                LocalClient::Geth(ref mut child) => drop(child.kill()),
            }
        }
    }

    fn chain_id_str(client_type: LocalClientType) -> String {
        match client_type {
            LocalClientType::Anvil => String::from("31337"),
            LocalClientType::Geth => String::from("1337"),
        }
    }

    fn start_local_client(l: LocalClientType, port: u16) -> LocalClient {
        match l {
            LocalClientType::Anvil => {
                let mut anvil: Option<AnvilInstance> = None;
                for _ in 0..10 {
                    let result = panic::catch_unwind(|| {
                        Anvil::new().port(port).arg("--steps-tracing").spawn()
                    });

                    match result {
                        Ok(a) => {
                            anvil = Some(a);
                            break;
                        }
                        Err(_) => {
                            // Wait for the other process to go away
                            println!("Waiting to start anvil");
                            sleep(Duration::from_millis(250));
                        }
                    }
                }
                let anvil = anvil.expect("Failed to start anvil");

                let mut config = DVFConfig::default();
                config.rpc_urls.insert(31337, anvil.endpoint());
                config.web3_timeout = 100;
                // Wait until it is up
                while let Err(e) = config.set_chain_id(31337) {
                    println!("Waiting for anvil config: {:?}", e);
                    sleep(Duration::from_millis(100));
                }
                LocalClient::Anvil(anvil)
            }
            _ => {
                // Start geth dev
                // geth --dev --http --http.api eth,web3,net,debug --http.port PORT --ipcpath /tmp/geth{port}.ipc
                println!("Starting geth setup");
                let ipc_path = format!("/tmp/geth{port}.ipc");
                let child = SimpleCommand::new("geth")
                    .arg("--dev")
                    .arg("--http")
                    .arg("--http.api")
                    .arg("eth,web3,net,debug")
                    .arg("--http.port")
                    .arg(port.to_string())
                    .arg("--ipcpath")
                    .arg(&ipc_path)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("Failed to spawn geth process");

                // Fund deployer account
                // geth --exec 'eth.sendTransaction({from: eth.accounts[0], to: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", value: web3.toWei(50, "ether")})' attach /tmp/geth.ipc

                let geth_command = "eth.sendTransaction({from: eth.accounts[0], to: \"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\", value: web3.toWei(50, \"ether\")})";

                // Build the command
                let mut command = SimpleCommand::new("geth");
                command
                    .arg("--exec")
                    .arg(geth_command)
                    .arg("attach")
                    .arg(&ipc_path)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());

                let mut worked = false;
                for _ in 0..10 {
                    // Spawn the command and handle race condition on startup
                    match command.output().unwrap().status.success() {
                        true => {
                            worked = true;
                            break;
                        }
                        false => {
                            println!("Waiting for first geth response");
                            sleep(Duration::from_millis(200))
                        }
                    }
                }
                if !worked {
                    panic!("Cannot fund geth account");
                }

                let geth_command = "eth.getBalance(\"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\")";
                // Build the command
                let mut command = SimpleCommand::new("geth");
                command
                    .arg("--exec")
                    .arg(geth_command)
                    .arg("attach")
                    .arg(&ipc_path);

                worked = false;
                for _ in 0..10 {
                    // Spawn the command and handle race condition on startup
                    match command.output() {
                        Ok(output) => {
                            if output.status.success()
                                && String::from_utf8(output.stdout)
                                    .unwrap()
                                    .starts_with("50000000000000000000")
                            {
                                worked = true;
                                break;
                            } else {
                                println!("Waiting to geth setup");
                                sleep(Duration::from_millis(200));
                            }
                        }
                        Err(_) => {
                            println!("Waiting to geth setup");
                            sleep(Duration::from_millis(200));
                        }
                    }
                }
                if !worked {
                    panic!("Cannot fund geth account");
                }

                println!("Geth setup complete.");
                LocalClient::Geth(child)
            }
        }
    }

    fn append_space(src_name: &str) {
        // Append a character to mess with the bytecode hashes
        let mut file = OpenOptions::new()
            .append(true) // Set the file to open in append mode
            .open(src_name)
            .unwrap(); // Specify the file path

        let character = ' '; // The character to append

        // Write the character to the file
        file.write_all(character.to_string().as_bytes()).unwrap();
    }

    fn truncate_last_byte(file_path: &str) {
        let file_size = metadata(file_path).unwrap().len();

        // Check if the file is not empty
        if file_size > 0 {
            let new_size = file_size - 1;
            let file = File::options().write(true).open(file_path).unwrap();
            file.set_len(new_size).unwrap();
        } else {
            println!("File is already empty (0 bytes).");
        }
    }

    fn assert_eq_files<P: AsRef<Path>>(path1: P, path2: P, l: LocalClientType) -> io::Result<()> {
        let file1 = File::open(path1)?;
        let file2 = File::open(path2)?;

        let reader1 = BufReader::new(&file1);
        let reader2 = BufReader::new(&file2);

        for (line_number, (line1, line2)) in reader1.lines().zip(reader2.lines()).enumerate() {
            let line1 = line1?;
            let line2 = line2?;

            // Code hashes and deployment txs can be different

            if !line1.contains("\"codehash\"") && !line1.contains("\"deployment_tx\"") {
                // Chain ID is different for geth
                if LocalClientType::Geth == l
                    && !(line1.contains("\"chain_id\":")
                        || line1.contains("\"deployment_block_num\":"))
                {
                    // don't compare codehash to avoid metadata mis-matches
                    assert_eq!(
                        line1,
                        line2,
                        "Line {}: \nFile1: {}\nFile2: {}",
                        line_number + 1,
                        line1,
                        line2
                    );
                }
            }
        }

        let reader1 = BufReader::new(file1);
        let reader2 = BufReader::new(file2);

        assert_eq!(
            reader1.lines().count(),
            reader2.lines().count(),
            "Differently many lines."
        );

        Ok(())
    }

    #[test]
    fn test_e2e_help() {
        let mut cmd = Command::cargo_bin("dv").unwrap();
        cmd.arg("--help").assert().success();
    }

    struct TestCaseE2E {
        script: String,
        contract: String,
        expected: String,
    }

    struct TestCaseE2EUpdate {
        script: String,
        contract: String,
        expected: String,
        updated: String,
    }

    struct TestCaseE2EHardhat {
        path: String,
        script: Vec<String>,
        contract: String,
        expected: String,
    }

    #[test]
    fn test_e2e_init_update_validate() {
        let port = 8546u16;
        let config_file = match DVFConfig::test_config_file(Some(port)) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };
        let mut testcases: Vec<TestCaseE2EUpdate> = vec![];

        testcases.push(TestCaseE2EUpdate {
            script: String::from("script/Deploy_0.s.sol"),
            contract: String::from("BytesMapping"),
            expected: String::from("tests/expected_dvfs/Deploy_0_b1.dvf.json"),
            updated: String::from("tests/expected_dvfs/Deploy_0_updated.dvf.json"),
        });

        testcases.push(TestCaseE2EUpdate {
            script: String::from("script/Deploy_1.s.sol"),
            contract: String::from("StringMapping"),
            expected: String::from("tests/expected_dvfs/Deploy_1_b1.dvf.json"),
            updated: String::from("tests/expected_dvfs/Deploy_1_updated.dvf.json"),
        });

        // testcases.push(TestCaseE2EUpdate {
        //    script: String::from("script/Deploy_2.s.sol"),
        //    contract: String::from("CrazyStruct"),
        //    expected: String::from("tests/expected_dvfs/Deploy_2_b1.dvf.json"),
        //    updated: String::from("tests/expected_dvfs/Deploy_2_updated.dvf.json"),
        // });

        testcases.push(TestCaseE2EUpdate {
            script: String::from("script/Deploy_3.s.sol"),
            contract: String::from("StructInEvent"),
            expected: String::from("tests/expected_dvfs/Deploy_3_b1.dvf.json"),
            updated: String::from("tests/expected_dvfs/Deploy_3_updated.dvf.json"),
        });

        testcases.push(TestCaseE2EUpdate {
            script: String::from("script/Deploy_4.s.sol"),
            contract: String::from("StaticArrayOfDynamicArray"),
            expected: String::from("tests/expected_dvfs/Deploy_4_b1.dvf.json"),
            updated: String::from("tests/expected_dvfs/Deploy_4_updated.dvf.json"),
        });

        testcases.push(TestCaseE2EUpdate {
            script: String::from("script/Deploy_5.s.sol"),
            contract: String::from("NestedMapping"),
            expected: String::from("tests/expected_dvfs/Deploy_5_b1.dvf.json"),
            updated: String::from("tests/expected_dvfs/Deploy_5_updated.dvf.json"),
        });

        testcases.push(TestCaseE2EUpdate {
            script: String::from("script/Deploy_6.s.sol"),
            contract: String::from("Enum"),
            expected: String::from("tests/expected_dvfs/Deploy_6_b1.dvf.json"),
            updated: String::from("tests/expected_dvfs/Deploy_6_updated.dvf.json"),
        });

        for testcase in testcases {
            let url = format!("http://localhost:{}", port).to_string();
            for client_type in LocalClientType::iterator() {
                let local_client = start_local_client(client_type.clone(), port);

                // forge script script/Deploy_0.s.sol --rpc-url "http://127.0.0.1:8546" --broadcast --slow
                let mut forge_cmd = Command::new("forge");
                forge_cmd.current_dir("tests/Contracts");
                let forge_assert = forge_cmd
                    .args(&[
                        "script",
                        &testcase.script,
                        "--rpc-url",
                        &url,
                        "--broadcast",
                        "--slow",
                    ])
                    .assert()
                    .success();
                println!(
                    "{}",
                    &String::from_utf8_lossy(&forge_assert.get_output().stdout)
                );

                let outfile = NamedTempFile::new().unwrap();
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                let assert = dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "init",
                        "--address",
                        "0x5fbdb2315678afecb367f032d93f642f64180aa3",
                        "--chainid",
                        &chain_id_str(client_type.clone()),
                        "--project",
                        "tests/Contracts/",
                        "--contractname",
                        &testcase.contract,
                        "--initblock",
                        "2",
                        &outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .success();
                println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));

                // Uncomment to regenerate expected files
                // std::fs::copy(outfile.path(), Path::new(&testcase.expected)).unwrap();

                assert_eq_files(
                    &outfile.path(),
                    &Path::new(&testcase.expected),
                    client_type.clone(),
                )
                .unwrap();

                // Sign
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                let assert = dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "sign",
                        &outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .success();
                println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));

                // Validate
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                let assert = dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "validate",
                        "--validationblock",
                        "2",
                        &outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .success();
                println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));

                // Update
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                let assert = dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "update",
                        "--validationblock",
                        "5",
                        &outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .success();
                println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));

                let updated_path = format!("{}_updated.dvf.json", outfile.path().to_string_lossy());

                // Uncomment to regenerate expected files
                // std::fs::copy(Path::new(&updated_path), Path::new(&testcase.updated)).unwrap();

                assert_eq_files(
                    &Path::new(&updated_path),
                    &Path::new(&testcase.updated),
                    client_type.clone(),
                )
                .unwrap();

                // Sign
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                let assert = dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "sign",
                        &updated_path,
                    ])
                    .assert()
                    .success();
                println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));

                // Validate
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                let assert = dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "validate",
                        "--validationblock",
                        "5",
                        &updated_path,
                    ])
                    .assert()
                    .success();
                println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));

                drop(local_client);
            }
        }
    }

    #[test]
    fn test_e2e_factory() {
        let port = 8547u16;
        let config_file = match DVFConfig::test_config_file(Some(port)) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };
        let url = format!("http://localhost:{}", port).to_string();
        for client_type in LocalClientType::iterator() {
            let local_client = start_local_client(client_type.clone(), port);

            // forge script script/Deploy_Factory.s.sol --rpc-url "http://127.0.0.1:8546" --broadcast
            let mut forge_cmd = Command::new("forge");
            forge_cmd.current_dir("tests/with_metadata");
            let forge_assert = forge_cmd
                .args(&[
                    "script",
                    "script/Deploy_Factory.s.sol",
                    "--rpc-url",
                    &url,
                    "--broadcast",
                    "--slow",
                ])
                .assert()
                .success();
            println!(
                "{}",
                &String::from_utf8_lossy(&forge_assert.get_output().stdout)
            );

            let src_name = "tests/with_metadata/src/PullPayment.sol";
            append_space(src_name);

            let factory_outfile = NamedTempFile::new().unwrap();
            let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
            let assert = dvf_cmd
                .args(&[
                    "--config",
                    &config_file.path().to_string_lossy(),
                    "init",
                    "--address",
                    "0x5fbdb2315678afecb367f032d93f642f64180aa3",
                    "--chainid",
                    &chain_id_str(client_type.clone()),
                    "--project",
                    "tests/with_metadata/",
                    "--contractname",
                    "PullPayment",
                    "--factory",
                    "--initblock",
                    "3",
                    &factory_outfile.path().to_string_lossy(),
                ])
                .assert()
                .success();
            println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));

            // Remove the extra byte again
            truncate_last_byte(src_name);

            assert_eq_files(
                &factory_outfile.path(),
                &Path::new("tests/expected_dvfs/PullPayment.dvf.json"),
                client_type.clone(),
            )
            .unwrap();

            // Sign
            let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
            dvf_cmd
                .args(&[
                    "--config",
                    &config_file.path().to_string_lossy(),
                    "sign",
                    &factory_outfile.path().to_string_lossy(),
                ])
                .assert()
                .success();

            // Validate
            let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
            dvf_cmd
                .args(&[
                    "--config",
                    &config_file.path().to_string_lossy(),
                    "validate",
                    &factory_outfile.path().to_string_lossy(),
                ])
                .assert()
                .success();
            drop(local_client);
        }
    }

    #[test]
    fn test_e2e_proxy() {
        let port = 8548u16;
        let config_file = match DVFConfig::test_config_file(Some(port)) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };
        let url = format!("http://localhost:{}", port).to_string();
        for client_type in LocalClientType::iterator() {
            let local_client = start_local_client(client_type.clone(), port);

            // forge script script/Deploy_Proxy.s.sol --rpc-url "http://127.0.0.1:8546" --broadcast
            let mut forge_cmd = Command::new("forge");
            forge_cmd.current_dir("tests/Contracts");
            let forge_assert = forge_cmd
                .args(&[
                    "script",
                    "script/Deploy_Proxy.s.sol",
                    "--rpc-url",
                    &url,
                    "--broadcast",
                    "--slow",
                ])
                .assert()
                .success();
            println!(
                "{}",
                &String::from_utf8_lossy(&forge_assert.get_output().stdout)
            );

            let outfile = NamedTempFile::new().unwrap();
            let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
            let assert = dvf_cmd
                .args(&[
                    "--config",
                    &config_file.path().to_string_lossy(),
                    "init",
                    "--address",
                    "0x5fbdb2315678afecb367f032d93f642f64180aa3",
                    "--chainid",
                    &chain_id_str(client_type.clone()),
                    "--project",
                    "tests/Contracts/",
                    "--initblock",
                    "3",
                    "--contractname",
                    "MyToken",
                    &outfile.path().to_string_lossy(),
                ])
                .assert()
                .success();
            println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));

            // Uncomment to regenerate expected files
            /*
            std::fs::copy(
                outfile.path(),
                Path::new("tests/expected_dvfs/MyToken.dvf.json"),
            )
            .unwrap();
            */

            assert_eq_files(
                &outfile.path(),
                &Path::new("tests/expected_dvfs/MyToken.dvf.json"),
                client_type.clone(),
            )
            .unwrap();

            // Sign
            let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
            dvf_cmd
                .args(&[
                    "--config",
                    &config_file.path().to_string_lossy(),
                    "sign",
                    &outfile.path().to_string_lossy(),
                ])
                .assert()
                .success();

            let token_dvf = CompleteDVF::from_path(outfile.path()).unwrap();
            let token_dvf_id = token_dvf.id.unwrap();
            let config = DVFConfig::from_path(&config_file.path()).unwrap();

            let mut new_dvf_path = config.dvf_storage.clone();
            new_dvf_path.push("MyToken.dvf.json");
            outfile.persist(new_dvf_path.as_path()).unwrap();

            let proxy_outfile = NamedTempFile::new().unwrap();
            let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
            let assert = dvf_cmd
                .args(&[
                    "--config",
                    &config_file.path().to_string_lossy(),
                    "init",
                    "--address",
                    "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512",
                    "--chainid",
                    &chain_id_str(client_type.clone()),
                    "--project",
                    "tests/Contracts/",
                    "--contractname",
                    "TransparentUpgradeableProxy",
                    "--implementation",
                    "MyToken",
                    "--initblock",
                    "3",
                    &proxy_outfile.path().to_string_lossy(),
                ])
                .assert()
                .success();
            println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));

            // Uncomment to regenerate expected files
            /*
            std::fs::copy(
                proxy_outfile.path(),
                Path::new("tests/expected_dvfs/TransparentUpgradeableProxy.dvf.json"),
            )
            .unwrap();
            */

            // @note that this fails, since the wrong name is stored in the registry
            assert_eq_files(
                &proxy_outfile.path(),
                &Path::new("tests/expected_dvfs/TransparentUpgradeableProxy.dvf.json"),
                client_type.clone(),
            )
            .unwrap();

            let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
            dvf_cmd
                .args(&[
                    "--config",
                    &config_file.path().to_string_lossy(),
                    "add-reference",
                    "--contractname",
                    "MyToken",
                    "--id",
                    &token_dvf_id,
                    &proxy_outfile.path().to_string_lossy(),
                ])
                .assert()
                .success();

            // Sign
            let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
            dvf_cmd
                .args(&[
                    "--config",
                    &config_file.path().to_string_lossy(),
                    "sign",
                    &proxy_outfile.path().to_string_lossy(),
                ])
                .assert()
                .success();

            // Validate
            let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
            dvf_cmd
                .args(&[
                    "--config",
                    &config_file.path().to_string_lossy(),
                    "validate",
                    &proxy_outfile.path().to_string_lossy(),
                ])
                .assert()
                .success();

            // Remove MyToken.dvf.json
            let mut rm_cmd = Command::new("rm");
            rm_cmd.arg(new_dvf_path.as_path()).assert().success();

            drop(local_client);
        }
    }

    #[test]
    fn test_e2e_init_validate() {
        let port = 8549u16;
        let config_file = match DVFConfig::test_config_file(Some(port)) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };

        let mut testcases: Vec<TestCaseE2E> = vec![];

        testcases.push(TestCaseE2E {
            script: String::from("script/Deploy_0.s.sol"),
            contract: String::from("BytesMapping"),
            expected: String::from("tests/expected_dvfs/Deploy_0.dvf.json"),
        });

        testcases.push(TestCaseE2E {
            script: String::from("script/Deploy_1.s.sol"),
            contract: String::from("StringMapping"),
            expected: String::from("tests/expected_dvfs/Deploy_1.dvf.json"),
        });

        // testcases.push(TestCaseE2E {
        //    script: String::from("script/Deploy_2.s.sol"),
        //    contract: String::from("CrazyStruct"),
        //    expected: String::from("tests/expected_dvfs/Deploy_2.dvf.json"),
        // });

        testcases.push(TestCaseE2E {
            script: String::from("script/Deploy_3.s.sol"),
            contract: String::from("StructInEvent"),
            expected: String::from("tests/expected_dvfs/Deploy_3.dvf.json"),
        });
        testcases.push(TestCaseE2E {
            script: String::from("script/Deploy_4.s.sol"),
            contract: String::from("StaticArrayOfDynamicArray"),
            expected: String::from("tests/expected_dvfs/Deploy_4.dvf.json"),
        });
        testcases.push(TestCaseE2E {
            script: String::from("script/Deploy_5.s.sol"),
            contract: String::from("NestedMapping"),
            expected: String::from("tests/expected_dvfs/Deploy_5.dvf.json"),
        });
        testcases.push(TestCaseE2E {
            script: String::from("script/Deploy_AllValueTypes.s.sol"),
            contract: String::from("AllValueTypes"),
            expected: String::from("tests/expected_dvfs/AllValueTypes.dvf.json"),
        });
        testcases.push(TestCaseE2E {
            script: String::from("script/Deploy_CrazyHiddenStruct.s.sol"),
            contract: String::from("CrazyHiddenStruct"),
            expected: String::from("tests/expected_dvfs/CrazyHiddenStruct.dvf.json"),
        });
        for testcase in testcases {
            let url = format!("http://localhost:{}", port).to_string();
            for client_type in LocalClientType::iterator() {
                let local_client = start_local_client(client_type.clone(), port);

                // forge script script/Deploy_0.s.sol --rpc-url "http://127.0.0.1:8546" --broadcast --slow
                let mut forge_cmd = Command::new("forge");
                forge_cmd.current_dir("tests/Contracts");
                let forge_assert = forge_cmd
                    .args(&[
                        "script",
                        &testcase.script,
                        "--rpc-url",
                        &url,
                        "--broadcast",
                        "--slow",
                    ])
                    .assert()
                    .success();
                println!(
                    "{}",
                    &String::from_utf8_lossy(&forge_assert.get_output().stdout)
                );

                let outfile = NamedTempFile::new().unwrap();
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                let assert = dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "init",
                        "--address",
                        "0x5fbdb2315678afecb367f032d93f642f64180aa3",
                        "--chainid",
                        &chain_id_str(client_type.clone()),
                        "--project",
                        "tests/Contracts/",
                        "--contractname",
                        &testcase.contract,
                        "--initblock",
                        "4",
                        &outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .success();
                println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));

                // Uncomment to regenerate expected files
                // std::fs::copy(outfile.path(), Path::new(&testcase.expected)).unwrap();

                assert_eq_files(
                    &outfile.path(),
                    &Path::new(&testcase.expected),
                    client_type.clone(),
                )
                .unwrap();

                // Sign
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "sign",
                        &outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .success();

                // Validate
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "validate",
                        "--validationblock",
                        "4",
                        &outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .success();
                drop(local_client);
            }
        }
    }

    #[test]
    fn test_e2e_init_invalid() {
        let port = 8550u16;
        let config_file = match DVFConfig::test_config_file(Some(port)) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };

        let mut testcases: Vec<TestCaseE2E> = vec![];

        testcases.push(TestCaseE2E {
            script: String::from("script/Deploy_0.s.sol"),
            contract: String::from("StringMapping"),
            expected: String::from("tests/expected_dvfs/Deploy_0.dvf.json"),
        });

        testcases.push(TestCaseE2E {
            script: String::from("script/Deploy_1.s.sol"),
            contract: String::from("BytesMapping"),
            expected: String::from("tests/expected_dvfs/Deploy_1.dvf.json"),
        });
        for testcase in testcases {
            let port = 8550u16;
            let url = format!("http://localhost:{}", port).to_string();
            for client_type in LocalClientType::iterator() {
                let local_client = start_local_client(client_type.clone(), port);

                // forge script script/Deploy_0.s.sol --rpc-url "http://127.0.0.1:8546" --broadcast
                let mut forge_cmd = Command::new("forge");
                forge_cmd.current_dir("tests/Contracts");
                let forge_assert = forge_cmd
                    .args(&[
                        "script",
                        &testcase.script,
                        "--rpc-url",
                        &url,
                        "--broadcast",
                        "--slow",
                    ])
                    .assert()
                    .success();
                println!(
                    "{}",
                    &String::from_utf8_lossy(&forge_assert.get_output().stdout)
                );

                let outfile = NamedTempFile::new().unwrap();
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                let assert = dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "init",
                        "--address",
                        "0x5fbdb2315678afecb367f032d93f642f64180aa3",
                        "--chainid",
                        &chain_id_str(client_type.clone()),
                        "--project",
                        "tests/Contracts/",
                        "--contractname",
                        &testcase.contract,
                        "--initblock",
                        "4",
                        &outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .failure();
                println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));

                drop(local_client);
            }
        }
    }

    #[test]
    fn test_e2e_validate() {
        let port = 8551u16;
        let config_file = match DVFConfig::test_config_file(Some(port)) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };

        let url = format!("http://localhost:{}", port).to_string();
        for client_type in LocalClientType::iterator() {
            let mut testcases: Vec<TestCaseE2E> = vec![];
            testcases.push(TestCaseE2E {
                script: String::from("script/Deploy_AllValueTypes.s.sol"),
                contract: String::from("AllValueTypes"),
                expected: format!(
                    "tests/expected_dvfs/AllValueTypes_operators_{}.dvf.json",
                    client_type.to_string()
                ),
            });
            for testcase in testcases {
                let local_client = start_local_client(client_type.clone(), port);

                // forge script script/Deploy_0.s.sol --rpc-url "http://127.0.0.1:8546" --broadcast --slow
                let mut forge_cmd = Command::new("forge");
                forge_cmd.current_dir("tests/Contracts");
                let forge_assert = forge_cmd
                    .args(&[
                        "script",
                        &testcase.script,
                        "--rpc-url",
                        &url,
                        "--broadcast",
                        "--slow",
                    ])
                    .assert()
                    .success();
                println!(
                    "{}",
                    &String::from_utf8_lossy(&forge_assert.get_output().stdout)
                );

                // Sign inside test so the regular file can remain unsigned
                let outfile = NamedTempFile::new().unwrap();
                let _ = std::fs::copy(
                    Path::new(&testcase.expected).to_string_lossy().as_ref(),
                    outfile.path().to_string_lossy().as_ref(),
                );
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "sign",
                        &outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .success();

                // Validate
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "validate",
                        "--validationblock",
                        "4",
                        &outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .success();
                drop(local_client);
            }
        }
    }

    #[test]
    fn test_e2e_failing_factory() {
        let port = 8552u16;
        let config_file = match DVFConfig::test_config_file(Some(port)) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };

        let url = format!("http://localhost:{}", port).to_string();
        for client_type in LocalClientType::iterator() {
            let local_client = start_local_client(client_type.clone(), port);

            // forge script script/Deploy_FailingCreate.sol --rpc-url "http://127.0.0.1:8546" --broadcast
            let mut forge_cmd = Command::new("forge");
            forge_cmd.current_dir("tests/Contracts");
            let forge_assert = forge_cmd
                .args(&[
                    "script",
                    "script/Deploy_FailingCreate.sol",
                    "--rpc-url",
                    &url,
                    "--broadcast",
                    "--slow",
                    "--legacy",
                ])
                .assert()
                .success();
            println!(
                "{}",
                &String::from_utf8_lossy(&forge_assert.get_output().stdout)
            );

            for deployed_address in [
                "0xeebe00ac0756308ac4aabfd76c05c4f3088b8883",
                "0x603e1bd79259ebcbaaed0c83eec09ca0b89a5bcc",
                "0x9cfa6d15c80eb753c815079f2b32ddefd562c3e4",
            ] {
                let src_name = "tests/Contracts/src/FailingCreate.sol";
                append_space(src_name);

                let child_outfile = NamedTempFile::new().unwrap();
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                let assert = dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "init",
                        "--address",
                        deployed_address,
                        "--chainid",
                        &chain_id_str(client_type.clone()),
                        "--project",
                        "tests/Contracts/",
                        "--contractname",
                        "WorkingChild",
                        "--initblock",
                        "5",
                        &child_outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .success();
                println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));

                // Remove the extra byte again
                truncate_last_byte(src_name);

                let new_fname = &format!(
                    "tests/expected_dvfs/WorkingChild_{}.dvf.json",
                    deployed_address
                );

                // Uncomment to regenerate expected files
                // std::fs::copy(child_outfile.path(), Path::new(new_fname)).unwrap();

                assert_eq_files(
                    &child_outfile.path(),
                    &Path::new(new_fname),
                    client_type.clone(),
                )
                .unwrap();

                // Sign
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "sign",
                        &child_outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .success();

                // Validate
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "validate",
                        &child_outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .success();
            }
            drop(local_client);
        }
    }

    #[test]
    fn test_pure_factory() {
        let port = 8553u16;
        let config_file = match DVFConfig::test_config_file(Some(port)) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };

        let url = format!("http://localhost:{}", port).to_string();
        for client_type in LocalClientType::iterator() {
            let local_client = start_local_client(client_type.clone(), port);

            // forge script script/Deploy_PureFactory.s.sol --rpc-url "http://127.0.0.1:8546" --broadcast --slow
            let mut forge_cmd = Command::new("forge");
            forge_cmd.current_dir("tests/with_metadata");
            let forge_assert = forge_cmd
                .args(&[
                    "script",
                    "script/DeployPureFactory.s.sol",
                    "--rpc-url",
                    &url,
                    "--broadcast",
                    "--slow",
                ])
                .assert()
                .success();
            println!(
                "{}",
                &String::from_utf8_lossy(&forge_assert.get_output().stdout)
            );

            for (contract_name, deployed_address, facarg, dvf_path) in [
                (
                    "PureDeployer",
                    "0x5fbdb2315678afecb367f032d93f642f64180aa3",
                    "--factory",
                    "tests/expected_dvfs/PureDeployer.dvf.json",
                ),
                (
                    "PureChild",
                    "0xa16e02e87b7454126e5e10d957a927a7f5b5d2be",
                    "",
                    "tests/expected_dvfs/PureChild.dvf.json",
                ),
            ] {
                let src_name = "tests/with_metadata/src/PureFactory.sol";
                append_space(src_name);

                let factory_outfile = NamedTempFile::new().unwrap();
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                dvf_cmd.args(&[
                    "--config",
                    &config_file.path().to_string_lossy(),
                    "init",
                    "--address",
                    deployed_address,
                    "--chainid",
                    &chain_id_str(client_type.clone()),
                    "--project",
                    "tests/with_metadata/",
                    "--contractname",
                    contract_name,
                    "--initblock",
                    "3",
                ]);
                if facarg.len() > 1 {
                    dvf_cmd.arg(facarg);
                }
                dvf_cmd.arg(factory_outfile.path());
                let assert = dvf_cmd.assert().success();
                println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));

                // Remove the extra byte again
                truncate_last_byte(src_name);

                // Uncomment to regenerate expected files
                // std::fs::copy(factory_outfile.path(), Path::new(dvf_path)).unwrap();

                assert_eq_files(
                    &factory_outfile.path(),
                    &Path::new(dvf_path),
                    client_type.clone(),
                )
                .unwrap();

                // Sign
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "sign",
                        &factory_outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .success();

                // Validate
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "validate",
                        &factory_outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .success();
            }
            drop(local_client);
        }
    }

    #[test]
    fn test_gen_e2e_expected() {
        let port = 8554u16;
        let config_file = match DVFConfig::test_config_file(Some(port)) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };

        let mut testcases: Vec<TestCaseE2E> = vec![];

        testcases.push(TestCaseE2E {
            script: String::from("script/Deploy_0.s.sol"),
            contract: String::from("BytesMapping"),
            expected: String::from("tests/expected_dvfs/Deploy_0.dvf.json"),
        });

        testcases.push(TestCaseE2E {
            script: String::from("script/Deploy_1.s.sol"),
            contract: String::from("StringMapping"),
            expected: String::from("tests/expected_dvfs/Deploy_1.dvf.json"),
        });

        // TODO: Bring all those back, when the anvil bug is fixed
        // testcases.push(TestCaseE2E {
        //    script: String::from("script/Deploy_2.s.sol"),
        //    contract: String::from("CrazyStruct"),
        //    expected: String::from("tests/expected_dvfs/Deploy_2.dvf.json"),
        // });

        testcases.push(TestCaseE2E {
            script: String::from("script/Deploy_3.s.sol"),
            contract: String::from("StructInEvent"),
            expected: String::from("tests/expected_dvfs/Deploy_3.dvf.json"),
        });
        testcases.push(TestCaseE2E {
            script: String::from("script/Deploy_4.s.sol"),
            contract: String::from("StaticArrayOfDynamicArray"),
            expected: String::from("tests/expected_dvfs/Deploy_4.dvf.json"),
        });
        testcases.push(TestCaseE2E {
            script: String::from("script/Deploy_5.s.sol"),
            contract: String::from("NestedMapping"),
            expected: String::from("tests/expected_dvfs/Deploy_5.dvf.json"),
        });
        for testcase in testcases {
            let url = format!("http://localhost:{}", port).to_string();
            for client_type in LocalClientType::iterator() {
                let local_client = start_local_client(client_type.clone(), port);

                // forge script script/Deploy_0.s.sol --rpc-url "http://127.0.0.1:8546" --broadcast
                let mut forge_cmd = Command::new("forge");
                forge_cmd.current_dir("tests/Contracts");
                let forge_assert = forge_cmd
                    .args(&[
                        "script",
                        &testcase.script,
                        "--rpc-url",
                        &url,
                        "--broadcast",
                        "--slow",
                    ])
                    .assert()
                    .success();
                println!(
                    "{}",
                    &String::from_utf8_lossy(&forge_assert.get_output().stdout)
                );

                let outfile = NamedTempFile::new().unwrap();
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                let assert = dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "init",
                        "--address",
                        "0x5fbdb2315678afecb367f032d93f642f64180aa3",
                        "--chainid",
                        &chain_id_str(client_type.clone()),
                        "--project",
                        "tests/Contracts/",
                        "--contractname",
                        &testcase.contract,
                        "--initblock",
                        "2",
                        &outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .success();
                println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));
                // outfile.keep().unwrap();
                drop(local_client);
            }
        }
    }

    #[test]

    fn test_e2e_init_initcode_invalid() {
        let port = 8555u16;
        let config_file = match DVFConfig::test_config_file(Some(port)) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };

        let testcase = TestCaseE2E {
            script: String::from("script/Deploy_MaliciousToken.s.sol"),
            contract: String::from("ERC20"),
            expected: String::from(""),
        };

        let url = format!("http://localhost:{}", port).to_string();
        for client_type in LocalClientType::iterator() {
            let local_client = start_local_client(client_type.clone(), port);

            // "forge" "script" "script/Deploy_MaliciousToken.s.sol" "--rpc-url" "http://localhost:8550" "--broadcast" "--slow"`
            let mut forge_cmd = Command::new("forge");
            forge_cmd.current_dir("tests/Contracts");
            let forge_assert = forge_cmd
                .args(&[
                    "script",
                    &testcase.script,
                    "--rpc-url",
                    &url,
                    "--broadcast",
                    "--slow",
                ])
                .assert()
                .success();
            println!(
                "{}",
                &String::from_utf8_lossy(&forge_assert.get_output().stdout)
            );

            let outfile = NamedTempFile::new().unwrap();
            let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
            let assert = dvf_cmd
                .args(&[
                    "--config",
                    &config_file.path().to_string_lossy(),
                    "init",
                    "--address",
                    "0xa16E02E87b7454126E5E10d957A927A7F5B5d2be",
                    "--chainid",
                    &chain_id_str(client_type.clone()),
                    "--project",
                    "tests/Contracts/",
                    "--contractname",
                    &testcase.contract,
                    "--initblock",
                    "3",
                    &outfile.path().to_string_lossy(),
                ])
                .assert()
                .failure();
            let output = String::from_utf8_lossy(&assert.get_output().stdout);
            println!("{}", &output);

            // The expected output should be Error occurred: Init code not matched for contract 0xa16e02e87b7454126e5e10d957a927a7f5b5d2be
            assert!(output.contains("Error occurred: Init code not matched for contract 0xa16e02e87b7454126e5e10d957a927a7f5b5d2be"), "The string does not contain the required text.");
            drop(local_client);
        }
    }

    #[test]
    fn test_hardhat() {
        let port = 8556u16;
        let config_file = match DVFConfig::test_config_file(Some(port)) {
            Ok(config) => config,
            Err(err) => {
                println!("{}", err);
                assert!(false);
                return;
            }
        };

        let mut testcases: Vec<TestCaseE2EHardhat> = vec![];

        testcases.push(TestCaseE2EHardhat {
            path: String::from("tests/hardhat"),
            script: vec![
                String::from("run"),
                String::from("scripts/Deploy_Hardhat.js"),
            ],
            contract: String::from("Hardhat"),
            expected: String::from("tests/expected_dvfs/Hardhat.dvf.json"),
        });

        testcases.push(TestCaseE2EHardhat {
            path: String::from("tests/hardhat"),
            script: vec![
                String::from("run"),
                String::from("scripts/Deploy_HardhatUp.js"),
            ],
            contract: String::from("HardhatUp"),
            expected: String::from("tests/expected_dvfs/HardhatUp.dvf.json"),
        });
        /*

                // test old Hardhat version 2.0
                testcases.push(TestCaseE2EHardhat {
                    path: String::from("tests/hardhat_2_0"),
                    script: vec![
                        String::from("run"),
                        String::from("scripts/Deploy_Hardhat.js"),
                    ],
                    contract: String::from("Hardhat"),
                    expected: String::from("tests/expected_dvfs/Hardhat_old.dvf.json"),
                });

                testcases.push(TestCaseE2EHardhat {
                    path: String::from("tests/hardhat_2_0"),
                    script: vec![
                        String::from("run"),
                        String::from("scripts/Deploy_HardhatUp.js"),
                    ],
                    contract: String::from("HardhatUp"),
                    expected: String::from("tests/expected_dvfs/HardhatUp_old.dvf.json"),
                });
        */
        for testcase in testcases {
            let port = 8556u16;
            for client_type in LocalClientType::iterator() {
                let local_client = start_local_client(client_type.clone(), port);

                // network is set in config
                let mut deploy_cmd = Command::new("npx");
                deploy_cmd.current_dir(testcase.path.clone());
                let forge_assert = deploy_cmd
                    .args(vec![String::from("hardhat")].iter().chain(&testcase.script))
                    .assert()
                    .success();
                println!(
                    "{}",
                    &String::from_utf8_lossy(&forge_assert.get_output().stdout)
                );

                let outfile = NamedTempFile::new().unwrap();
                let mut dvf_cmd = Command::cargo_bin("dv").unwrap();
                let assert = dvf_cmd
                    .args(&[
                        "--config",
                        &config_file.path().to_string_lossy(),
                        "init",
                        "--address",
                        "0x5fbdb2315678afecb367f032d93f642f64180aa3",
                        "--chainid",
                        &chain_id_str(client_type.clone()),
                        "--project",
                        &testcase.path,
                        "--contractname",
                        &testcase.contract,
                        "--env",
                        "hardhat",
                        "--initblock",
                        "2",
                        &outfile.path().to_string_lossy(),
                    ])
                    .assert()
                    .success();
                println!("{}", &String::from_utf8_lossy(&assert.get_output().stdout));

                // Uncomment to regenerate expected files
                // std::fs::copy(outfile.path(), Path::new(&testcase.expected)).unwrap();

                assert_eq_files(
                    &outfile.path(),
                    &Path::new(&testcase.expected),
                    client_type.clone(),
                )
                .unwrap();

                drop(local_client); // this will kill the instance
            }
        }
    }
}
