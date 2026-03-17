# Generating the Test Attack Path with Metric-FF

This section describes how to generate a test plan using **Metric-FF 2.0** from the provided AED domain and AEDI problem instances.

------

## 1. Environment Setup

### System Requirements

- macOS or Linux (recommended)
- OR Windows (via WSL or MinGW)
- GCC compiler installed
- Make utility installed

To verify GCC:

```bash
gcc --version
```

To verify Make:

```bash
make --version
```

------

## 2. Download Metric-FF 2.0

Download Metric-FF 2.0 from our replication package:

```
https://github.com/SuperCorleone/SAQURE/...
```

Unzip the downloaded archive:

```bash
tar -xvf Metric-FF-v2.0.tgz
```

This will create a directory named `Metric-FF`.

------

## 3. Compile Metric-FF

Navigate to the directory and compile:

```bash
cd Metric-FF
make
```

If compilation succeeds, an executable file named `ff` (or `ff.exe` on Windows) will be generated.

Test installation:

```bash
./ff
```

You should see usage instructions printed in the terminal.

------

## 4. Data Preparation

Ensure the following files are available locally:

- `AED.pddl` (domain file)
- `AEDIs/spoofing.pddl` or `tampering.pddl` or `repudiation` or `information-disclosure` or `denial-of-service.pddl` or `elevation-of-privilege.pddl` (problem file)
- Output directory `AP/`

Recommended directory structure:

```
.../
│
├── Metric-FF/
│   └── ff
│
├── AED.pddl
├── AEDIs/
│   └── spoofing.pddl
│
└── AP/
```

Create output folder if needed:

```bash
mkdir -p AP
```

------

## 5. Metric-FF Command Format

The basic command structure is:

```bash
./ff -o <domain-file> -f <problem-file> -s 4 -w 4
```

### Parameter Explanation

- `-o` : domain file
- `-f` : problem file
- `-s 4` : enforced hill-climbing with helpful actions
- `-w 4` : heuristic weight (recommended setting used in our experiments)

------

## 6. Run Metric-FF

### 6.1 On macOS / Linux

From the `Metric-FF` directory:

```bash
./ff -o ../AED.pddl \
     -f ../AEDIs/spoofing.pddl \
     -s 4 -w 4 \
     > ../AP/test-ap.pddl
```

The generated test plan will be saved to:

```
AP/test-ap.pddl
```

------

### 6.2 On Windows

### Option 1 (Recommended): Windows Subsystem for Linux (WSL)

Install WSL and follow the macOS/Linux instructions.

------

### Option 2: Windows Command Prompt (MinGW)

After compiling with `make`, run:

```bash
ff.exe -o ..\AED.pddl ^
       -f ..\AEDIs\spoofing.pddl ^
       -s 4 -w 4 ^
       > ..\AP\test-ap.pddl
```

Note:

- `^` is the line continuation symbol in Windows CMD.
- Alternatively, write the command in a single line.

