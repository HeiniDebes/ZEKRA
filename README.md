# ZEKRA

This repository accompanies the paper "ZEKRA: Zero-Knowledge Control-Flow Attestation".

## Directory Structure

The directory structure of the ZEKRA repository is as follows:

 * [embench-iot-applications](embench-iot-applications): contains a select subset of applications from [embench-iot](https://github.com/embench/embench-iot/)
 * [scripts](scripts/): contains a set of helper scripts written in Python 3
   * [poseidon](scripts/poseidon/): module is a Python implementation of the Poseidon hashing function \[1]
   * [circuit_input_formatter.py](scripts/circuit_input_formatter.py): script to format inputs for the ZEKRA circuit (including the hashing)
   * [compile_circuit.py](scripts/compile_circuit.py): script to compile a ZEKRA circuit
   * [extractor.py](scripts/extractor.py): script to (1) compile an application and then (2) extract its CFG and a sample execution path
 * [zekra_java](zekra_java): contains the produced java files for ZEKRA after transforming the xJsnark code to java code using xJsnark's front-end extension of the MPS Framework.
 * [zekra_xjsnark](zekra_xjsnark): contains the high-level ZEKRA program code written in the xJsnark framework
   * [readable](zekra_xjsnark/readable/): contains the ZEKRA program code in a readable format (without having to install [xjsnark](https://github.com/akosba/xjsnark) and [JetBrains MPS 3.3](https://confluence.jetbrains.com/display/MPS/JetBrains+MPS+3.3+Download+Page))
   * [zekra.mps](zekra_xjsnark/zekra.mps): the actual ZEKRA program code written using the [xjsnark](https://github.com/akosba/xjsnark) library
 * [setup.sh](setup.sh): shell script to install all dependencies
 * [xjsnark_backend.jar](xjsnark_backend.jar): the xJsnark backend for compiling circuits

## Table of Contents

- [ZEKRA](#zekra)
  - [Directory Structure](#directory-structure)
  - [Table of Contents](#table-of-contents)
  - [Setting up the environment](#setting-up-the-environment)
  - [Extracting Control-Flow Graphs and sample execution paths](#extracting-control-flow-graphs-and-sample-execution-paths)
    - [Example (Reproducing our Results)](#example-reproducing-our-results)
    - [Output](#output)
  - [Preparing inputs to the ZEKRA circuit](#preparing-inputs-to-the-zekra-circuit)
    - [Command example](#command-example)
    - [Command output](#command-output)
    - [Output files](#output-files)
  - [Compiling the ZEKRA circuit](#compiling-the-zekra-circuit)
    - [Command example](#command-example-1)
    - [Command output](#command-output-1)
    - [Output files](#output-files-1)
  - [Executing/Profiling the ZEKRA circuit using jsnark's inferface to libsnark's implementation of Groth16](#executingprofiling-the-zekra-circuit-using-jsnarks-inferface-to-libsnarks-implementation-of-groth16)
  - [Editing the ZEKRA xjsnark program code](#editing-the-zekra-xjsnark-program-code)
  - [References](#references)
  - [Disclaimer](#disclaimer)

## Setting up the environment

To generate a circuit from the [zekra_java](zekra_java) code using the [xjsnark_backend.jar](xjsnark_backend.jar), it is necessary to have Java installed. Furthermore, to work with the generated circuit using the [libsnark/jsnark_interface](https://github.com/akosba/libsnark/tree/master/libsnark/jsnark_interface) (e.g., to generate the proving and verification keys for the circuit and also generate and verify proofs), both jsnark (libsnark) and its dependencies must be properly setup as described [here](https://github.com/akosba/libsnark#build-instructions). However, to make things easier, the shell script [setup.sh](setup.sh) includes the necessary commands to setup jsnark, its dependencies, a simple java environment, and the Python 3 packages necessary to run the helper scripts, such as the [angr](https://github.com/angr/angr) package to extract the [static CFG](https://docs.angr.io/built-in-analyses/cfg) from binaries and also to extract an example execution path through [symbolic execution](https://docs.angr.io/core-concepts/pathgroups).

To run the script, execute the following commands (tested on Ubuntu 20.04):

```
chmod +x setup.sh
./setup.sh
```

## Extracting Control-Flow Graphs and sample execution paths

```
Usage: scripts/extractor.py [options]
Options:
  -h               This help message
  -v               Verbose output
  -d <path/to/dir> Directory containing target applications organized into folders (default is to consider the './embench-iot-applications' directory)
  -a <path>        Path to specific target application
  -e <name1,name2> Comma separated list of application folders to exclude
```

### Example (Reproducing our Results)

We used the demonstrative application from the open source benchmarking suite [embench-iot](https://github.com/embench/embench-iot/) (with minor modifications) in our paper to demonstrate our circuit's applicability for such deeply embedded applications. We provide the set of applications used in the [embench-iot-applications](embench-iot-applications) directory. To reproduce the datasets used in our paper, we recommend using our [extractor.py](scripts/extractor.py) script to compile each application binary and extract its CFG and example execution path, as follows:

```
python3 scripts/extractor.py -d ./embench-iot-applications
```

It is also possible to target only a specific application, as follows:

```
python3 scripts/extractor.py -a ./embench-iot-applications/crc32
```

### Output

For each application, the [extractor.py](scripts/extractor.py) script will generate the following files in the targeted application's directory:

- `adjlist`: containing the raw adjacency list (hex addresses)
- `numified_adjlist`: containing an example transformation of the raw adjacency list to a numerically labeled adjacency list
- `numified_path`: containing the labeled execution path as translated using the translator mapping
- `recorded_path`: containing the raw execution path (hex addresses)
- `translator`: containing the mapping between the raw and numified adjacency list
- `stats.log`: containing a copy of the stats which are printed to stdout during command execution

Below you can see the contents of `./embench-iot-applications/crc32/stats.log` after executing the command `python3 scripts/extractor.py -a ./embench-iot-applications/crc32`:

```
./embench-iot-applications/crc32
Min addr: 0x400000
Max addr: 0x807fff (bitwidth=24)
CFG has 88 nodes and 106 edges
Adjacency list max_neighbors: 2 ['3', '4']
Bucket-rems pairs (levels) required to express the encoded adjacency list: 2
Execution path died because it: reached an exit
Execution path length pre compression: 3090
Number of consecutively repeated sequences: 1
Average (mean) length of sequences: 3.00 (std=0.00)
Average (mean) number of sequence repetitions: 1023.00 (std=0.00)
Execution path length post compression: 24
Max stack depth: 6
Execution path is valid according to the adjlist: True
```

## Preparing inputs to the ZEKRA circuit

```
Usage: scripts/circuit_input_formatter.py -a <dir> [options]
Options:
  -h                       This help message
  -a <dir>                 Path to specific target application's directory containing the 'adjlist', 'numified_adjlist', 'translator', 'recorded_path', and 'numified_path' files
  --pad-adjlist-to <len>   Pad the adjlist and translator with zeros (empty entries) until their length is <len> (default is to not pad)
  --pad-path-to <len>      Pad the execution path with zeros (empty moves) until its length is <len> (default is to not pad)
  --adjlist-levels <num>   Use <num> levels (pairs of bucket-rems) for encoding the adjacency list. Note that this primarily affects the adjacency list compression which is done prior to hashing to reduce the number of calls to Poseidon (default is to use the minimum levels necessary to maximize compression and minimize the size of the generated circuit)
  --output-dir <dir>       Store the circuit input files in <dir> (default is to store the files in the same directory as the targeted application)
  --nonce-verifier <num>   Verifier's nonce to hash with the execution path (default 0)
  --nonce-path <num>       Blinding factor (nonce) to hash with the execution path (default 0)
  --nonce-translator <num> Blinding factor (nonce) to hash with the address-to-label translator (default 0)
  --nonce-adjlist <num>    Blinding factor (nonce) to hash with the encoded adjacency list (default 0)
  --label-bitwidth <num>   Use <num> bits to represent each numified destination address when compressing/hashing the numified execution path (default is to use the minimum number of bits as determined by the size of the adjacency list).
  --bucket-bitwidth <num>  Use <num> bits to represent each quotient (bucket) in the adjacency list encoding (default is to use the miminum number of bits as determined by the length of the adjacency list).
  --address-bitwidth <num> Use <num> bits to represent each destination address when compressing/hashing the raw/recorded execution path (default is to use the minimum number of bits as determined by the recorded execution path provided as input).
```

### Command example

For example, to prepare the circuit inputs adjacency list to fit a circuit data structure that supports up to 500 nodes, use 15 levels to represent each node's encoded neighbors (with 7-bit buckets on each level), support execution paths comprising 500 transitions (with 24-bit addresses), and supporting a shadow stack depth of 15, execute the following command:

```
python3 scripts/circuit_input_formatter.py \
  -a ./embench-iot-applications/crc32/ \
  --pad-adjlist-to 500 \
  --pad-path-to 500 \
  --adjlist-levels 15 \
  --nonce-verifier 12353 \
  --nonce-path 123 \
  --nonce-translator 123 \
  --nonce-adjlist 123 \
  --label-bitwidth 10 \
  --bucket-bitwidth 7 \
  --address-bitwidth 24
```
### Command output

Below is an example of the above command's output:

```
The input adjacency list contains 500 entries/nodes (i.e., max label is 500, which occupies 9 bits)
The maximum address in the input adjacency list is 0x601060 and occupies 23 bits
Minimum:     ADJLIST_LEVELS=2 LABEL_BITWIDTH=9 BUCKET_BITWIDTH=6 ADDR_BITWIDTH=23
Considering: ADJLIST_LEVELS=15 LABEL_BITWIDTH=10 BUCKET_BITWIDTH=7 ADDR_BITWIDTH=24

The encoded adjacency list contains 500 nodes (88 without padding)
Wrote encoded adjacency list to file './embench-iot-applications/crc32/in_encoded_adjlist'
Starting hashing of the encoded adjacency list
        neighbors_bitwidth: 225 (15 levels * (7-bit buckets + 8-bit rems))
        elems_per_field_element: 1 (using 254-bit p)
        occupies 500 field elements after compression
        padding compressed path with 4 additional field elements (Poseidon call has arity 8 and we need to reserve 1 element for the adjacency list nonce)
        calls to Poseidon needed: 63
Wrote encoded adjlist digest to file './embench-iot-applications/crc32/in_encoded_adjlist_digest'
Encoded adjacency list hash: 5985449892039608890456185764561858730723264824691156509074284478893635440892
The translator contains 501 addresses (88 without padding)
Wrote translator to file './embench-iot-applications/crc32/in_translator'
Starting hashing of the translator
        ADDR_BITWIDTH: 24
        elems_per_field_element: 10 (using 254-bit p)
        occupies 51 field elements after compression
        padding translator with 5 additional field elements (Poseidon call has arity 8 and we need to reserve 1 element for the translator nonce)
        calls to Poseidon needed: 7
Wrote translator digest to file './embench-iot-applications/crc32/in_translator_digest'
Translator hash: 5551575237474407726413860559067084002486780251770875449597188721978322980717
The numified execution path contains 500 transitions (24 without padding)
Wrote numified execution path to file './embench-iot-applications/crc32/in_numified_path'
Wrote initial node = 0 to file './embench-iot-applications/crc32/in_initial_node'
Wrote final node = 72 to file './embench-iot-applications/crc32/in_final_node'
Wrote verifier's nonce to file './embench-iot-applications/crc32/in_nonce_verifier'
Wrote execution path's nonce to file './embench-iot-applications/crc32/in_nonce_path'
Wrote translator's nonce to file './embench-iot-applications/crc32/in_nonce_translator'
Wrote adjacency list's nonce to file './embench-iot-applications/crc32/in_nonce_adjlist'
The recorded execution path contains 500 transitions (24 without padding)
Wrote recorded execution path to file './embench-iot-applications/crc32/in_recorded_path'
Starting hashing of the execution path
        transition_bitwidth: 50 (2-bit jumpkind||24-bit dest address||24-bit ret address)
        elems_per_field_element: 5 (using 254-bit p)
        occupies 100 field elements after compression
        padding compressed path with 4 additional field elements (Poseidon call has arity 8 and we need to reserve 2 elements for the verifier and execution path nonces)
        calls to Poseidon needed: 13
Wrote recorded execution path digest to file './embench-iot-applications/crc32/in_recorded_path_digest'
Recorded execution path hash: 21393937064302472340191694070938458033674045799645644822430973995137600407803
```

### Output files

As shown in the above command output, for each application, the [circuit_input_formatter.py](scripts/circuit_input_formatter.py) script will store the following, additional files to `output-dir/`:

- `output-dir/in_encoded_adjlist`: the encoded adjacency list
- `output-dir/in_encoded_adjlist_digest`: Poseidon hash of the encoded adjacency list (post padding)
- `output-dir/in_final_node`: containing the final (exit) node of the input execution path
- `output-dir/in_initial_node`: containing the initial (starting) node of the input execution path
- `output-dir/in_nonce_adjlist`: containing the encoded adjacency list's nonce (blinding factor)
- `output-dir/in_nonce_path`: containing the execution path's nonce (blinding factor)
- `output-dir/in_nonce_translator`: containing the address-to-label translator's nonce (blinding factor)
- `output-dir/in_nonce_verifier`: containing the verifier's nonce
- `output-dir/in_numified_path`: the execution path already translated into its numeric form (which is verified against the translator inside the circuit)
- `output-dir/in_recorded_path`: containing the recorded (raw) execution path
- `output-dir/in_recorded_path_digest`: Poseidon hash of the recorded execution path (post padding)
- `output-dir/in_translator`: the translator
- `output-dir/in_translator_digest`: Poseidon hash of the address-to-label translator (post padding)

## Compiling the ZEKRA circuit

**Note:** The [compile_circuit.py](scripts/compile_circuit.py) Python script compiles the ZEKRA circuit using the [xjsnark_backend.jar](xjsnark_backend.jar) and thus requires an existing Java environment (see preceding section). Furthermore, the command requires [xjsnark_backend.jar](xjsnark_backend.jar) to be in the current working directory.

```
Usage: scripts/compile_circuit.py --adjlist-len <num> --adjlist-levels <num> --path-len <num> --stack-depth <num> --label-bitwidth <num> --bucket-bitwidth <num> --address-bitwidth <num> [options]
Options:
  -h                       This help message
  -v                       Output also how the workload (in number of constraints) is distributed among the six individual ZEKRA components/gadgets
  --zekra-dir <dir>        Path to the directory containing the ZEKRA Java files (default is ./zekra)  --adjlist-len <num>      Set <num> as the number of nodes in the adjacency list (adjacency lists < max must be padded before being passed as input)
  --adjlist-levels <num>   Set <num> as the number of levels used to represent each node's neighbors in the adjacency list
  --path-len <num>         Set <num> as the number of transitions in the execution path (execution paths < max must be padded before being passed as input)
  --stack-depth <num>      Set <num> as the maximum depth of the shadow stack data structure (execution paths that surpass this upper bound will cause the proof to become rejected so it must be set appropriately)
  --label-bitwidth <num>   Set <num> as the number of bits to represent each numified destination address when compressing/hashing the numified execution path
  --bucket-bitwidth <num>  Set <num> as the number of bits to represent each quotient (bucket) in the adjacency list encoding
  --address-bitwidth <num> Set <num> as the number of bits to represent each destination address when compressing/hashing the raw/recorded execution path
  --input-dir <dir>        Directory containing the output files from 'circuit_input_formatter.py' (default is to check the current working directory)
  --output-dir <dir>       Store the <zekra.arith> and <zekra_Sample_Run1> files in <dir> (default is to store the files in the current working directory)
  --components-dir <dir>   If -v is used, then <dir> is the path to the directory containing the different ZEKRA components 'zekra_c1,...,zekra_c6' (default is ./components)
```

### Command example

For example, to prepare the ZEKRA circuit with an adjacency list data structure to support 500 nodes, use 15 levels to represent each node's encoded neighbors, support execution paths comprising 500 transitions, and supporting a shadow stack depth of 15, execute the following command (xjsnark will also prepare the circuit inputs from `input-dir` to be supplied to libsnark):

```
python3 scripts/compile_circuit.py \
  --zekra-dir zekra_java/zekra \
  --adjlist-len 500 \
  --adjlist-levels 15 \
  --path-len 500 \
  --stack-depth 15 \
  --label-bitwidth 10 \
  --bucket-bitwidth 7 \
  --address-bitwidth 24 \
  --input-dir ./embench-iot-applications/crc32 \
  --components-dir zekra_java/components \
  -v
```

### Command output

Below is an example of the above command's output:

```
Successfully compiled the ZEKRA circuit.
Total constraints: 336230
Arithmetic circuit stored in: zekra.arith
Formatted inputs stored in: zekra_Sample_Run1.in

Compiling individual components to find workload distribution.
Component #1's constraints: 25513 (7.6% of total)
Component #2's constraints: 5263 (1.6% of total)
Component #3's constraints: 2833 (0.8% of total)
Component #4's constraints: 128668 (38.3% of total)
Component #5's constraints: 108089 (32.1% of total)
Component #6's constraints: 65864 (19.6% of total)
```

### Output files

The [compile_circuit.py](scripts/compile_circuit.py) script will store the following files to `output-dir/`:

- `output-dir/zekra.arith`: containing the generated ZEKRA arithmetic circuit
- `output-dir/zekra_Sample_Run1.in`: containing the formatted inputs to the circuit

## Executing/Profiling the ZEKRA circuit using jsnark's inferface to libsnark's implementation of [Groth16](https://github.com/akosba/libsnark/tree/master/libsnark/zk_proof_systems/ppzksnark)

Usage:

```
./jsnark/libsnark/build/libsnark/jsnark_interface/run_ppzksnark gg \
    zekra.arith \
    zekra_Sample_Run1.in
```

Where, given a circuit definition `<zekra.arith>` and formatted inputs `<zekra_Sample_Run1.in>` (from [Compiling the ZEKRA circuit](#compiling-the-zekra-circuit)), the called procedure will profile the execution of the following algorithms: key generation, proof generation, and proof verification.

--------------------------------------------------------------------------------
Editing the ZEKRA [xjsnark](https://github.com/akosba/xjsnark) program code
--------------------------------------------------------------------------------

To directly edit or compile the [zekra.mps](zekra_xjsnark/zekra.mps) program code, follow these instructions:

1. First download (or clone) [xjsnark](https://github.com/akosba/xjsnark) and follow its installation instructions, which includes an installation of [JetBrains MPS 3.3](https://confluence.jetbrains.com/display/MPS/JetBrains+MPS+3.3+Download+Page).
2. Copy the [zekra.mps](zekra_xjsnark/zekra.mps) file to `xjsnark/languages/xjsnark/sandbox/models/xjsnark`. 
3. Open the [xjsnark](https://github.com/akosba/xjsnark) project in [JetBrains MPS 3.3](https://confluence.jetbrains.com/display/MPS/JetBrains+MPS+3.3+Download+Page).
4. Right-click `xjsnark` in the project viewer and click "Rebuild Language 'xjsnark'".
5. Expand the `zekra` module under `xjsnark.sandbox` and open the `zekra.zekra` program.
6. Perform any modifications/improvements/expansions:
7. After performing any modications, you must right-click the `zekra` module and click "Rebuild Model 'xjsnark.zekra'".
8. Then, to compile the modified ZEKRA program code, right-click the `zekra.zekra` program and click "Run 'Class zekra'", which will generate the same output files as before in a directory of your choosing, namely:
    - `zekra.arith`: containing the ZEKRA arithmetic circuit.
    - `zekra_Sample_Run1.in`: containing the formatted inputs to the ZEKRA arithmetic circuit.

--------------------------------------------------------------------------------
References
--------------------------------------------------------------------------------

\[1] [
  _POSEIDON: A New Hash Function for Zero-Knowledge Proof Systems_
](https://eprint.iacr.org/2019/458.pdf),
  Lorenzo Grassi, Dmitry Khovratovich, Christian Rechberger, Arnab Roy, and Markus Schofnegger,
  USENIX Security Symposium 2021

--------------------------------------------------------------------------------
Disclaimer
--------------------------------------------------------------------------------

This is an early release that could contain issues and inconsistencies. The implementations provided in this repository are currently only research prototypes.
