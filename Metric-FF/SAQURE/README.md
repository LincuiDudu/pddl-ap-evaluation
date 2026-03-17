# SAQURE — replication package

This package contains the raw data as well as scripts used to replicate the results presented in the following research paper:

"SAQURE: Real-Time AI-Driven Environment-Aware Self-Adaptation for Security and QoS", Anonymous Author(s) 


### Structure

The package contains software (`Java` sources) and data (logs analyzable with `python` scripts). The package has the following structure.
* `prism/`: `PRISM` models of SEFA and TeaStore, and properties used to calculate the long-term risk;
* 'Metric-FF/': ;
* 'attack_goals/': ;
* 'plan/': ;
* 'domain/': ; 
* `ramses-planner-simulator/`: `Gradle` project of the extended version of `RAMSES` including the implementation of the method `SAQURE` with MAPE-K modules;
* `experiments/`: 'bash' and `python` scripts that quickly run the different sub-experiments and generate the plots presented in the paper.

### Instructions

To build the sources of `RAMSES` you need the [Gradle build tool](https://gradle.org/). From the directory `ramses-planner-simulator` you can run:

```
gradle clean build
```

To replicate the results of all the experiments in the paper you can run seperately (which might take few minutes):

'''
./experiments/run_experiments/run_all_rq1.sh
./experiments/run_experiments/run_all_rq2.sh
./experiments/run_experiments/run_all_rq3.sh
./experiments/run_experiments/run_all_rq4.sh
'''

To generate all plots from the data you need [Python 3](https://www.python.org/). You can run:

```
python3 experiments/plots/create_plot_RQ1.py
python3 experiments/plots/create_plot_RQ2.py
python3 experiments/plots/create_plot_RQ3.py
python3 experiments/plots/create_plot_RQ4.py
```

All the plots are generated in `.png` format in the same directory.
