# BH2024: Projet 22: Enabling sensitive data access from Galaxy to (F)EGA

## Abstract

In an era marked by the continuous growth of precision medicine and the emergence of regulations such as the GDPR and EHDS, the implementation of secure repositories to enable data sharing has become essential. These protocols play a crucial role in preserving the confidentiality of sensitive information and effectively mitigating risks associated with unauthorised access and data breaches.

Galaxy is one of the most popular analysis platforms, especially among non-bioinformatics specialists. Thus, to increase Galaxy's integration within environments that require stringent data security measures, this proposal devises a comprehensive strategy that would facilitate the secure and scalable access and processing of sensitive datasets (and their derivative sensitive results) within Galaxy.

Integral to this endeavour is the European Genome-Phenome Archive (EGA), recognised as the predominant repository within Europe for the secure storage phenoclinical and genomics data, thus underscoring its significance in biomedical data security considerations. As data housed within EGA federated repositories is encrypted in accordance with the GA4GH Crypt4GH standard, the proposed strategy is the development of a protocol tailored to enable the secure access, transfer, and processing of encrypted datasets, thereby leveraging the capabilities of a multi-user public Galaxy platform.

## Project Objectives

The objective of the project can be divided into two milestones: 
1. Development of a workflow that connects EGA, either central or any federated node, and Galaxy through Crypt4GH protocols.
2. Galaxy's secure processing protocol: Sensitive datasets are kept encrypted throughout, with sensitive derivative results labelled as sensitive.

## Resources

1. [About Galaxy](https://docs.galaxyproject.org/en/master/).
2. [About EGA](https://localega.readthedocs.io/en/latest/).
3. [About GA4GH Crypt4GH](https://crypt4gh.readthedocs.io/en/latest/).
4. [Slack Channel](https://biohackeu.slack.com/archives/C07NBGJKE0Z) - Use this as the main source of communication between in-person and virtual participants during the hackathon.

## Leads

María Chavero-Díez (ELIXIR-ES) Sveinung Gundersen, Pável Vázquez Faci (ELIXIR-NO)
