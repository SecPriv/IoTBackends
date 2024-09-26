# IoTBackends

The following repository contains the code for the backends analysis presented at RAID 2024 in scope of the paper "Large-Scale Security Analysis of Real-World Backend Deployments Speaking IoT-Focused Protocols".
How to cite the [paper](raid2024-iot-backends.pdf):

```
@inproceedings{backends:raid2024,
  title     = {{Large-Scale Security Analysis of Real-World Backend Deployments Speaking IoT-Focused Protocols}},
  author    = {Tagliaro, Carlotta and Komsic, Martina and Continella, Andrea and Borgolte, Kevin and Lindorfer, Martina},
  booktitle = {Proceedings of the 27th International Symposium on Research in Attacks, Intrusions and Defenses (RAID)},
  location  = {Padua, Italy},
  year      = {2024},
  doi       = {10.1145/3678890.3678899}
}
```

## Directory Structure:

The folder [polished code](polished%20code) contains all the scripts that we used to collect the Shodan backends, evaluate their security and compute statistics and draw plots. For more details information, navigate to each folder where a specific README file is present. All scripts are written in Python and use version 3.10.12.

Additionally, the [paper in PDF format](raid2024-iot-backends.pdf) is present in the main folder.

## CVD Efforts - WTMC 2024

A follow up of the paper, on the Coordinate Vulnerability Disclosure (CVS) efforts we made, was also published at the 9th International Workshop on Traffic Measurements for Cybersecurity (co-located with EuroS&P 2024). We make the [PDF](disclosure_wtmc24.pdf) available. How to cite the paper:

```
@inproceedings{disclosure:wtmc2024,
  title     = {{Are You Sure You Want To Do Coordinated Vulnerability Disclosure?}},
  author    = {Chen, Ting-Han Chen and Tagliaro, Carlotta and Lindorfer, Martina and Borgolte, Kevin and van der Ham-de Vos, Jeroen},
  booktitle = {Proceedings of the 9th International Workshop on Traffic Measurements for Cybersecurity (WTMC)},
  location  = {Vienna, Austria},
  year      = {2024},
  doi       = {10.1109/EuroSPW61312.2024.00039}
}
```

### NOTE:

Code is still under work in progress for clean-up. Further, to avoid de-anonymization of vulnerable backends, only aggregated results are present in the repository, thus limiting the successful execution of the scripts. If interested in more details or in the traffic PCAPs for the backends we analyzed, please contact us (contact information below).

#### Contact Information:

Carlotta Tagliaro, TUWien (carlotta@seclab.wien or carlotta.tagliaro@tuwien.ac.at)