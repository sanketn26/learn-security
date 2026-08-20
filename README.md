# Defensive Security Engineering

[![Buy Me A Coffee](https://img.shields.io/badge/☕-Buy%20me%20a%20coffee-FFDD00?style=flat-square)](https://buymeacoffee.com/sanketn)

Hands-on cybersecurity course for experienced software, platform, backend,
DevOps, and ML engineers. You will learn how modern attacks work, how systems
are defended, how security operations run, how to investigate events, and how
to build a small end-to-end monitoring and response platform on a laptop.

**Start with the [onboarding guide](docs/onboarding.md)**, then read
[COURSE.md](docs/course.md) (roadmap). Each of Modules 1–17 opens with a
**Visual overview** (diagrams, intuition, hints) before its text; complete
them in order, then the [capstone](docs/capstone/README.md).

Labs are local, defensive, and isolated. Read [docs/ethics.md](docs/ethics.md)
before starting. Offensive steps are **AUTHORIZED LAB USE ONLY**.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-docs.txt
make docs

# In another terminal, when you are ready for the lab:
chmod +x labs/scripts/*.sh
make lab-up
curl -s http://127.0.0.1:8080/.well-known/lab
```

| Resource | Path |
| --- | --- |
| Beginner onboarding | [docs/onboarding.md](docs/onboarding.md) |
| Setup and first lab | [docs/setup.md](docs/setup.md) |
| Learning paths | [docs/learning-paths.md](docs/learning-paths.md) |
| Course overview and comparisons | [docs/course.md](docs/course.md) |
| Ethics and scope | [docs/ethics.md](docs/ethics.md) |
| Lab environment | [docs/lab-guide.md](docs/lab-guide.md) |
| Modules | [docs/modules/](docs/modules/) |
| Capstone | [docs/capstone/README.md](docs/capstone/README.md) |
| Glossary | [docs/glossary.md](docs/glossary.md) |
| References | [docs/references.md](docs/references.md) |
| One-page plan | [docs/condensed-plan.md](docs/condensed-plan.md) |

License: MIT (see [LICENSE](LICENSE)). Dummy lab secrets are not real
credentials. Vendored asset notices are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
