# Threat model — notes-api (fill in)

## Diagram

```
[analyst] --> 127.0.0.1:8090/8091
[user]    --> 127.0.0.1:8080 --> notes-api --> sqlite
                                   |  (should not)
                                   +------> mock-imds
                                   +------> JSONL --> soc-lite --> agent
```

## Assets

| Asset | Sensitivity |
| --- | --- |
| Note bodies | High in prod; dummy in lab |
| Password hashes | High |
| JWT signing secret | High |
| Dummy IMDS keys | Treat as high for practice |

## Trust boundaries

| From | To | Control today | Residual |
| --- | --- | --- | --- |
| User | API | JWT (weak in LAB_MODE) | Stolen token |
| API | object | Owner check only if LAB_MODE=false | IDOR |
| API | IMDS | App block if LAB_MODE=false; safety rail always | Other internals |
| App host | logs | volume | attacker with volume access |

## Top threats

1.
2.
3.
4.
5.

## Residual risk statement

_Write one paragraph._
