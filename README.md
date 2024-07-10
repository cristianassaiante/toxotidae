# toxotidae

This repository is the future home of **Toxotidae**, a prototype API monitor for malware analysis.

Our cutting-edge tool offers unique capabilities in monitoring API invocations, even when facing sophisticated attacks aimed at compromising completeness and correctness, with a low performance overhead compared to previously available monitoring tools.
Our solution employs a static analysis approach that meticulously traces parameters propagation with high precision, and select multiple program points, within the control-flow graph of Windows APIs, to be hooked to guarantee the effective log of the API calls obfuscated with the novel attacks proposed in the manuscript.

The methodology behind this tool is described in the paper [Evading Userland API Hooking, Again: Novel Attacks and a Principled Defense Method]() that will appear in the DIMVA '24 conference. The code will be released by the conference start date.

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
