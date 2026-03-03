# ZeroMint Quick Start

## Welcome to ZeroMint!

This tutorial will guide you through setting up and running your first vulnerability scan using ZeroMint.

### Prerequisites
Let's install the dependencies. The repository is already cloned to your environment.

Run the following command in the terminal to install `zeromint`:

```bash
pip install -e ".[dev]"
```

<walkthrough-test-commands>pip show zeromint</walkthrough-test-commands>

### Initialization
Next, let's create a default configuration file.

```bash
zeromint init
```

### Run your first scan

You are now ready to run the full analysis pipeline. By default, the `config.yaml` is set up to scan the `sample_targets` directory using a Dummy LLM for testing.

Execute the pipeline:

```bash
zeromint run -c config.yaml
```

Once the run completes, you can explore the generated `REPORT.md` and `evidence_bundle.zip` in the `runs/` directory!

<walkthrough-conclusion-trophy></walkthrough-conclusion-trophy>
