# Agent Permission Analyzer

Analyze agent permission scopes for over-privileged permissions.

## Features

- Parse JSON permission grants (IAM-style policies)
- Detect over-privileged permissions: wildcards, network access, shell/exec access
- Risk scoring (0-100) based on severity of findings
- CLI tool for analyzing permission files

## Usage

```bash
pip install agent-permission-analyzer
python -m src.cli permissions.json
```

### Input Format (permissions.json)

```json
[
  {
    "Effect": "Allow",
    "Action": ["s3:GetObject"],
    "Resource": ["arn:aws:s3:::bucket/*"]
  }
]
```

### Example Output

```json
{
  "risk_score": 65,
  "findings": [
    {
      "type": "wildcard_action",
      "severity": "high",
      "detail": "Permission 's3:*' matches wildcard_action"
    }
  ],
  "recommendations": [
    "Remove wildcard actions - specify explicit permissions"
  ]
}
```

## Testing

```bash
pytest tests/ -v --cov=src --cov=80%
```

## Security

- Uses synthetic/test data only
- No real credentials or production systems

## License

MIT
