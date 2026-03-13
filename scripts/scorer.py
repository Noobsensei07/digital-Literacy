"""
Digital Literacy App — Scoring Model
-------------------------------------
Receives a JSON array of answered questions on stdin, each containing:
  { "question_score": 0 | 1, "difficulty_weight": <number> }

Calculates:  score = correct_answers_count * 2  (flat 2 points per correct answer)

Outputs a JSON object:  { "final_score": <number> }
"""

import sys
import json


def calculate_score(answers: list) -> float:
    """Return flat 2 points per correct answer."""
    correct_count = sum(1 for ans in answers if int(ans.get("question_score", 0)) == 1)
    return correct_count * 2


def main():
    try:
        raw = sys.stdin.read()
        answers = json.loads(raw)

        if not isinstance(answers, list):
            raise ValueError("Input must be a JSON array.")

        final_score = calculate_score(answers)

        print(json.dumps({"final_score": final_score}))
    except json.JSONDecodeError as e:
        print(json.dumps({"error": f"Invalid JSON: {str(e)}"}), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
