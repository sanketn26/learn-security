# Defensive Security Engineering

Hands-on cybersecurity course for experienced software, platform, backend,
DevOps, and ML engineers. You will learn how modern attacks work, how systems
are defended, how security operations run, how to investigate events, and how
to build a small end-to-end monitoring and response platform on a laptop.

**Start with [COURSE.md](COURSE.md)** (roadmap and conceptual spine), then
`modules/01` … `14`, then [capstone/README.md](capstone/README.md).

Labs are local, defensive, and isolated. Read [docs/ethics.md](docs/ethics.md)
before starting. Offensive steps are **AUTHORIZED LAB USE ONLY**.

```bash
chmod +x labs/scripts/*.sh
make lab-up
curl -s http://127.0.0.1:8080/.well-known/lab
```

| Resource | Path |
| --- | --- |
| Course overview and comparisons | [COURSE.md](COURSE.md) |
| Ethics and scope | [docs/ethics.md](docs/ethics.md) |
| Lab environment | [labs/README.md](labs/README.md) |
| Modules | [modules/](modules/) |
| Capstone | [capstone/README.md](capstone/README.md) |
| Glossary | [docs/glossary.md](docs/glossary.md) |
| References | [docs/references.md](docs/references.md) |
| One-page plan | [docs/condensed-plan.md](docs/condensed-plan.md) |

License: MIT (see [LICENSE](LICENSE)). Dummy lab secrets are not real
credentials.
