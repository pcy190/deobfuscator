# deobfuscator

## Introduction

Flexible deobfuscator.

## Feature


|         | x86 | x86_64 | arm | arm64 |
| ------- | --- | ------ | --- | ----- |
| deflat  | TODO | TODO | PARTLY | :heavy_check_mark: |


- [x] two engine mode for deflat
- [x] flexible patch pattern
- [x] easy to port

## Usage:

requirements:
- python3.7 +
- dependencies:
```
pip3 install qiling angr termcolor
```

modify the start address and filename in `main.py`, and 
```
python3 main.py
```

Specify the strategy `0` or `1` in `emulator.search_path`, in order to handle different flatten cases.

## TODO:

- support x86, x86_64 
- support Bogus Control Flow deobfuscation
- add blocks analysis manually
- IDAPro plugin, in order to mark the blocks visually by interacting with the deobfuscator (to handle different ida python version)
