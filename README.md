# IoTBackends

The following repository contains the code for the backends analysis presented at RAID 2024 in scope of the paper "Large-Scale Security Analysis of Real-World Backend Deployments Speaking IoT-Focused Protocols".
How to cite the paper:

```biblatex
@inproceedings{tagliaro:raid2024:backends,
  title={{Large-Scale Security Analysis of Real-World Backend Deployments Speaking IoT-Focused Protocols }},
  author={Tagliaro, Carlotta and Komsic, Martina and Continella, Andrea and Borgolte, Kevin and Lindorfer, Martina},
  year={2024},
  booktitle={Proc. of the 27th International Symposium on Research in Attacks, Intrusions and Defenses (RAID)}
}
```

## Directory Structure:

The folder `polished code` contains all the scripts that we used to collect the Shodan backends, evaluate their security and compute statistics and draw plots. For more details information, navigate to each folder where a specific README file is present. All scripts are written in Python and use version 3.10.12.

Additionally, the paper PDF is present in the main folder.

### NOTE:

Code is still under work in progress for clean-up. Further, to avoid de-anonymization of vulnerable backends, only aggregated results are present in the repository, thus limiting the successful execution of the scripts. If interested in more details or in the traffic PCAPs for the backends we analyzed, please contact us (contact information below).

#### Contact Information:

Carlotta Tagliaro, TUWien (carlotta@seclab.wien or carlotta.tagliaro@tuwien.ac.at)