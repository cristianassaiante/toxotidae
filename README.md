# toxotidae

This repository is the future home of **Toxotidae**, a prototype API monitor for malware analysis.

Our cutting-edge tool offers unique capabilities in monitoring API invocations, even when facing sophisticated attacks aimed at compromising completeness and correctness, with a low performance overhead compared to previously available monitoring tools.
Our solution employs a static analysis approach that meticulously traces parameters propagation with high precision, and select multiple program points, within the control-flow graph of Windows APIs, to be hooked to guarantee the effective log of the API calls obfuscated with the novel attacks proposed in the manuscript.

The methodology behind this tool is described in the paper [Evading Userland API Hooking, Again: Novel Attacks and a Principled Defense Method](https://link.springer.com/chapter/10.1007/978-3-031-64171-8_8https://link.springer.com/chapter/10.1007/978-3-031-64171-8_8) that will appear in the DIMVA '24 conference.

## Project Structure

Here, we provide an overview of every component of this repository. If you find something wrong, or you would like to contribute to this project, please fill an issue in this repository or send a PR! We would be really happy about that!

### Parsing the DLLs

Most of the components of this project make use of a disassembler and some sort of visit of the CFG of the functions under the scope. For this purpose, we build a [script](src/analysis-framework/parse_exports.py) that parses the APIs exported by Windows DLLs, and builds a convenient CFG representation that can be further analyzed efficiently and with none to zero effort from the programmer perspective. Each DLL is exported into a pickle file that can be easily accessed with the provided [library](src/analysis-framework/static_analyzer/) what lives within the analysis framework.

#### Requirements

The parse script uses the IDA Pro python interface to extract the CFGs, as well as the information automatically extracted by IDA from the DLLs' PDB files.

### Static Analyzer

The folder [static_analyzer](src/static_analyzer/) contains the source code of the analyses described in the manuscript: the fixed-point parameter propagation algorithm, the liveness analysis and the hook spot finder.

The project is set up in such a way that the actual code for the analysis is completely architecture agnostic. In fact, the algorithms, which implementation reside in the [analysis](src/analysis-framework/static_analyzer/analysis/) folder, do not use any functionality that is strictly related to a specific architecture.

All the source code related to x86, is in the [arch/x86](src/analysis-framework/static_analyzer/arch/x86/) folder where there are the scripts for [computing](src/analysis-framework/static_analyzer/arch/x86/compute_unit.py) the basic blocks and single instructions and the set of [registers](src/analysis-framework/static_analyzer/arch/x86/register.py) and [instructions](src/analysis-framework/static_analyzer/arch/x86/utils.py) provided by the target architecture.

With this code organization, the framework is, eventually, easily expandable to support other architectures, different from x86, with modest coding effort and without the need of re-adapting the principled method proposed.

#### Requirements

The external requirements needed by the tool are: the `capstone` disassembler, used to disassemble the APIs instructions and retrieve all the required information about the operands involved, and the `networkx` library, used to store and easily navigate through the CFGs of the APIs.

```console
$ pip install -r src/analysis-framework/requirements.txt
```

#### How to run

The [analysis](src/analysis.py) script takes as input the pickle file of the DLL to be analyzed. It computes each one of the algorithms, and produces all the stats, presented in the manuscript supporting this work. Eventually, the debug flag can enable debug prints, showing the analyses progress.

Example:
```console
$ cd src/analysis-framework
$ python analysis.py --dll somedll.dll.pickle --out somedll.dll.analyzed.pickle [--debug]
```

Once each dll is analyzed, it is possible to compute the hooks in the format parsed Toxotidae (every output pickle must be placed in a new directory).

Example
```console
$ cd src/analysis-framework
$ mkdir -p hooks/32bit
$ mkdir -p hooks/64bit
$ python format_hooks.py <path to directory with 32bit analyzed pickles>
$ python format_hooks.py <path to directory with 64bit analyzed pickles>
```

At this point, a directory `hooks` is created and Toxotidae can be set up.

### Toxotidae: API Monitor

Our main contribution is *Toxotidae*, an API monitor that can counter both stolen code and TOCTTOU attack by placing deeper hooks in optimal spots in the CFG, to avoid being evaded by adversaries.

The tool works given the hooks computed with the aforementioned [analysis](#static-analyzer), it [parses](src/toxotidae/hooks_parser.cpp#L87) the spots in a format generated by the analysis tool, and it instruments all the required instructions.
When a [hook is hit](src/toxotidae/hooks.cpp#L19), the API is logged together with the parameters available at that specific location.

Beside the computed hooks, the monitor is configured to always log APIs also on-entry (just like state-of-the-art and commercial monitoring tools do). We used this to evaluate the correctness of the tool using as target the wine tests suite.

When the application under analysis performs stolen code techniques, the on-entry hook will not be hit, thus identification of programs protected with such adversarial approach is trivial.

When the application under analysis performs TOCTTOU attacks, the on-entry hook will log the fake parameters provided at call site, while deeper hooks will log the intended parameters, unveiling the ongoing attack.

#### Requirements

The tool was built in VisualStudio17, for Intel PIN v3.19, and it requires it to be downloaded and extracted in `C:\`.
Moreover, since the monitor parses the hook spots from files generated by the static-analyzer (with the provided [script](src/analysis-framework/format_hooks.py)), the hooks directory needs to be placed in `C:\`.

#### How to run

Once the VS project is built, the pintool can be found in the PIN directory and goes under the name `tracer64.dll` for monitoring 64bit applications and `trarcer32.dll` for monitoring 32bit applications.

```console
> pin.exe -t tracer64.dll -- <path to exe to be monitored>
```

Eventually, Toxotidae can also be configured to log only on-entry. We used this to evaluate its performance against currently available approaches.

```console
> pin.exe -t tracer64.dll --onlyentry -- <path to exe to be monitored>
```

EXTRA: the tool can also instrument indirect `call` or `jmp` instructions to try to detect stolen code attacks that do make use of such paradigm. This functionality is *not* used for the purpose of this work. It can be enabled with the `--unjmp` flag.

## Cite
To reference our work, we would be grateful if you could use the following BibTeX code:

```
@inproceedings{10.1007/978-3-031-64171-8_8,
  author="Assaiante, Cristian and Nicchi, Simone and D'Elia, Daniele Cono and Querzoni, Leonardo",
  editor="Maggi, Federico and Egele, Manuel and Payer, Mathias and Carminati, Michele",
  title="Evading Userland API Hooking, Again: Novel Attacks and a Principled Defense Method",
  booktitle="Detection of Intrusions and Malware, and Vulnerability Assessment",
  year="2024",
  publisher="Springer Nature Switzerland",
  address="Cham",
  pages="150--173",
  abstract="Monitoring how a program utilizes userland APIs is behind much dependability and security research. To intercept and study their invocations, the established practice targets the prologue of API implementations for inserting hooks. This paper questions the validity of this design for security uses by examining completeness and correctness attacks to it. We first show how evasions that jump across the hook instrumentation are practical and can reach places much deeper than those we currently find in executables in the wild. Next, we propose and demonstrate TOCTTOU attacks that lead monitoring systems to observe false indicators for the argument values that a program uses for API calls. To mitigate both threats, we design a static analysis to identify vantage points for effective hook placement in API code, supporting both reliable call recording and accurate argument extraction. We use this analysis to implement an open-source prototype API monitor, Toxotidae, that we evaluate against adversarial and benign executables for Windows.",
  isbn="978-3-031-64171-8"
}
```
