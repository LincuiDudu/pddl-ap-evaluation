# TODOs

Solve in order and move to next phase as soon as previous is done.

- [ ] Stardardise data automatically to latest PDDL standards
    - Do it (semi)automatically with CLI AI-tools (Coder, Claude, ...)
- [ ] Data cleaninig and preprocessing tool
    - Remove unused lines of code
    - Remove comments
    - Remove empty lines
    - Standardize intentation and parentheses
- [ ] Interfaces to LLMs
    - Look into Marco's code
- [ ] Evaluation notebook (prompt and attack path)
    - Prepare code to simulate and test different evaluation strategies
    - Look into all the mentioned metrics and implement them
    - Try to implement batched evaluation wherever possible 
    - Look into Marco's code
- [ ] Data notebook (analysis)
    - Prepare code to compute baseline performances on the ground truth data
    - Prepare code to extract thresholds to maximise performances
    - Look into Marco's code
- [ ] Generation notebook (prompt and attack path)
    - Given iterfaces and data test prompt and generation
    - Use small models (even < 1B size) to proprype
    - Look into Marco's code
- [ ] Prepare command line tools to implement everything we tested through the notebooks
    - Take efficiency into account (multiple calls to LLM and loading the models will slow down process a lot)
    - Look into Marco's code
- [ ] Prepare bash scripts to run all the experiments based on the previous scripts
    - Make sure all steps are autoamtic, no human intervention