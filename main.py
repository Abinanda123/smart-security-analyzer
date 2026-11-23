import argparse
import json
from agent.analyzer import SecurityAgent

def main():
    # 1. Set up the terminal command arguments
    parser = argparse.ArgumentParser(description="AI Judge - Automated Security Scan Filter")
    parser.add_argument("--input", required=True, help="Path to the JSON file containing scanner results")
    parser.add_argument("--output", default="ai_report.json", help="Path to save the AI's final report")
    args = parser.parse_args()

    # 2. Read the findings from the provided file
    try:
        with open(args.input, "r") as f:
            findings = json.load(f)
    except FileNotFoundError:
        print(f"Error: Could not find the file '{args.input}'")
        return

    print(f"Loaded {len(findings)} findings from {args.input}. Initializing AI Judge...\n")
    agent = SecurityAgent()
    
    final_report = []

    # 3. Loop through every finding and ask the AI to judge it
    for finding in findings:
        finding_id = finding.get('id', 'Unknown ID')
        print(f"Analyzing {finding_id} in {finding.get('file')}...")
        
        rag_context = finding.get("context", "")
        
        # Call your Groq AI engine
        ai_verdict = agent.run_analysis(finding=finding, rag_results=rag_context)
        
        print(f" --> Verdict: {ai_verdict.get('verdict')} (Confidence: {ai_verdict.get('confidence')})\n")
        
        # Combine the original finding with the AI's verdict
        final_report.append({
            "scanner_data": finding,
            "ai_analysis": ai_verdict
        })

    # 4. Save the combined results to a new file
    with open(args.output, "w") as f:
        json.dump(final_report, f, indent=2)
        
    print(f"Batch processing complete! Full report saved to {args.output}")

if __name__ == "__main__":
    main()