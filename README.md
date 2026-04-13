# URLChecker-Tools <img src="contrib/logo.png" width="100" alt="URLChecker-Tools logo" />

URLChecker-Tools is a collection of tools that will be leveraged by the URLChecker Public Service:

url-checker-tools is a Python CLI security analysis toolkit that performs comprehensive URL threat assessment through
multi-source intelligence gathering. The tool queries external security APIs to collect threat intelligence data.
It also includes of POC of leveraging custom YARA rule sets for local content inspection and pattern matching.
It synthesizes findings from multiple sources into a unified and configurable security scoring and detailed report,
providing actionable insights about URL safety. Designed as the backend engine for security analysis, it delivers
structured JSON output compatible with automated workflows. Built for integration with the url-checker web platform,
it serves as the heavy-lifting component for asynchronous security assessments. But the Command Line Interface also
enables standalone usage for security researchers, incident response teams and personal usage.

## Getting started

## Collaboration, Contributing
- Our Definition of Done (DoD) is:
  - Tested,
  - ideally, Reviewed (mandatory in the applicable context),
  - Merged to ```main``` and Deployable from ```main``` if a new version was to be Released (see below).

- We follow Gitlab Flow for collaboration which is a [text](VERSION)simplification of the GitFlow, making it easier to couple with
DevOps and CI/CD principles (https://about.gitlab.com/topics/version-control/what-is-gitlab-flow/)
  - On top of that, we maintain files like ```RELEASE_NOTES.md```and ```UPGRADING_NOTES.md```,
  - With Gitblab UI, we release a new version from ```main``` branch on top of a version Git tag,
  - A new version can be associated to Gitlab Milestone to which various tasks and issues were done,
  - The Makefile recipe ```bump_version``` can be used to bump the new version and create the new version commit in a
  standardized way and in order to reduce overhead with Gitlab GUI to the maximum,
  - A merge to ```main``` creates a new commit in ```main``` and triggers the Build, Test and Deliver stages in
  ```main``` branch (so a successful pipeline after merging can be seen as a final step of our DoD approach),
  - A new commit related to the version bump, in ```main``` branch, also triggers these stages of CI/CD.

- In an effort of transparency and collaboration promotion, we maintain the file ```CONTRIBUTORS.md``` to keep a sense
of accountability accross team while:
  - keeping in the light people who actively contributed to the repository,
  - avoiding to maintain dupplicate headers in each file with redundant things like ```version```, ```ownership```, etc.

- We share the same Development configuration by using pre-commit hooks. In practice::
  - it is the responsibility of the Developper to configure its own IDE so that the pre-configured formatter
  and linter does not complain (the later ```Security and formatting/linting pipelines```)
  - the Developper needs therefore configure the pre-commit locally so that he can correct its formatting and code
  patterns with the feedback provided by Formatters and Linters.

- Contribution are therefore welcomed in the form of opening Gitlab Issues and if possible providing the code that solve
the point: a Merge Request is then opened based on the Issue. It might be necessary to group Issues into a bigger Epic.

## Development

A development helper is provided in the form of a Makefile.
Inspiration is taken from (MIT License, see contrib subfolders, license files kept for legacy), improvements from it will be backported:
- [my-devops-playground/makedeb-a-la-spoti](https://gitlab.com/tCR-lux/my-devops-playground/-/tree/master/Python/makedeb-a-la-spoti) Copyright © Cédric Renzi
- [my-devops-playground/packpy-src](https://gitlab.com/tCR-lux/my-devops-playground/-/tree/master/Python/packpy-src) Copyright © Cédric Renzi

Type ```make help``` from the king directory of this repository in order to get more insights.

## Test and Deploy

### Security and formatting/linting pipelines (TODO Gitlab -> GitHub)
Each commit pushed to any branch triggers:
- a Secret scanner,
- a Security scanner,
- a formatting and linting block of task. In case this fails, the pipeline does not go further.

### Building, Testing and Delivering pipelines (TODO Gitlab -> GitHub)
- Each commit to any branch triggers Tests (which does not require Build with Python and which allow to provide faster
Testing results to the Developper). It is advised to rely on the same Test mechanism both in CI/CD and on the local
Development environment (example: launcher script),
- A new commit in the ```main``` branch triggers ```Build``` and ```Deliver``` stages.

### Deployment
The deployment is kept manual with the brother repository ```urlchecker```

### Badges (tbd)
The status of the repository is easily identifiable with badges calculated at each pipeline runs and displayed in the
```README.md```.

## Documentation

{{ Mode detailed documentation is created in the ```doc``` folder. A ```Makefile``` helper is provided to construct
documentation on top of the content of this folder }}

## Product general description
## Product vision
The Product Vision is provided on NGSOTI/Restena websites.

## Roadmap
The Roadmap is maintained on GitHub in the shape of future milestones, associated future releases, and GitHub Issues
and/or Epics and/or defined Tasks associated to the Milestone.

## License

This software is licensed under [GNU Affero General Public License version 3](http://www.gnu.org/licenses/agpl-3.0.html)

```
Copyright (C) 2026 Fondation Restena
Copyright (C) 2026 Cédric Renzi
```

See details in LICENSE file for 3rd parties.

As mentionned in the collaboration section above, the Contributors hall-of-fame is maintained separately
the file ```CONTRIBUTORS.md```.

## Funding

URLChecker-tools is co-funded by [Restena](https://www.restena.lu/) and by the European Union under [NGSOTI](https://restena.lu/fr/project/ngsoti) (Next Generation Security Operator Training Infrastructure) project.

![EU logo](https://www.vulnerability-lookup.org/images/eu-funded.jpg)
![NGSOTI logo](https://restena.lu/files/styles/large/public/inline-images/ngsoti-logo-verti-col.png)
![Restena logo](https://restena.lu/sites/restena.lu/themes/site_theme/images/logo.svg)
