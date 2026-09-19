from app.analysis.rules.base import SecurityRule


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, SecurityRule] = {}

    def register(self, rule: SecurityRule) -> None:
        if rule.rule_id in self._rules:
            raise ValueError(f"Duplicate rule id: {rule.rule_id}")
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> SecurityRule | None:
        return self._rules.get(rule_id)

    def all(self) -> tuple[SecurityRule, ...]:
        return tuple(self._rules.values())

    def clear(self) -> None:
        self._rules.clear()

    def __len__(self) -> int:
        return len(self._rules)
