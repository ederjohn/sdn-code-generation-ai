# sdn-code-generation-ai

Repository for the paper **Trust, But Verify: An Empirical Evaluation of AI-Generated Code for SDN Controllers**.

Authors: Felipe A. Soares and Muriel F. Franco and Eder J. Scheid and Lisandro Z. Granville


## 🧠 Overview

This project aims to evaluate the generation of SDN network code using artificial intelligence models.  
The goal is to reduce manual effort when writing controller or topology code, accelerating prototyping and experimentation.

### Repository Structure

- `prompts` — Set of prompts used for code generation.  
- `topologies.py` — Network topology definitions.  
- `topologies_backup.py` — Backup or previous version for reference.  
- `generated-code/` — Stores automatically generated code.  
- Other scripts and experimental files related to the generation workflow.


## ⚠️ Notes and Limitations

- **Human review is mandatory.**  
  Automatically generated code may contain syntax errors, vulnerabilities, or unexpected behaviors.  
- This is an **experimental project**, intended to explore both the potential and the limitations of code generation for programmable networks.

## 🤝 Contributing

Contributions are welcome!  
You can help by:

- Adding new network topologies.  
- Improving or documenting the prompts.  
- Integrating new AI models or SDN frameworks.  
- Creating automated tests for generated code.  
- Documenting best practices and known issues.

Open a *pull request* or *issue* with your proposal.

## 📄 License

Apache 2.0. See LICENSE file.


## 📬 Contact

For questions, suggestions, or collaborations, use the **Issues** tab or reach out directly.
