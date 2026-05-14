from pathlib import Path
import sys

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _resolve_input_file(filename: str) -> Path:
    """Find an input file in the current directory or common project folders."""
    candidates = [
        Path.cwd() / filename,
        Path(__file__).resolve().parent / filename,
        PROJECT_ROOT / filename,
        PROJECT_ROOT / "Sprint2_Template" / filename,
        PROJECT_ROOT / "Sprint_Data" / filename,
    ]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    searched = "\n".join(f"- {candidate}" for candidate in candidates)
    raise FileNotFoundError(
        f"Could not find '{filename}'. Searched:\n{searched}"
    )

def generate_burndown(backlog_file, changelog_file, output_image_name):
    # 1. Load the data
    backlog_path = _resolve_input_file(backlog_file)
    changelog_path = _resolve_input_file(changelog_file)

    backlog = pd.read_csv(backlog_path)
    changelog = pd.read_csv(changelog_path)
    changelog['Timestamp'] = pd.to_datetime(changelog['Timestamp'])

    # Map Story IDs to their Point Estimates
    estimates = dict(zip(backlog['Story ID'], backlog['Estimate (SP)']))

    # 2. Identify items added mid-sprint to find our true "Day 1" starting SP
    added_tasks = changelog[changelog['Change Type'] == 'task add']['Item ID'].tolist()
    initial_sp = backlog[~backlog['Story ID'].isin(added_tasks)]['Estimate (SP)'].sum()

    # 3. Define the sprint timeline
    start_date = pd.to_datetime(backlog['Start Date']).min().floor('D')
    end_date = pd.to_datetime(backlog['End Date']).max().ceil('D')
    date_range = pd.date_range(start_date, end_date)

    daily_sp = []
    current_sp = initial_sp

    # 4. Iterate through each day of the sprint
    for current_date in date_range:
        # Get all changes that happened on this specific day
        day_changes = changelog[changelog['Timestamp'].dt.floor('D') == current_date]
        
        for _, row in day_changes.iterrows():
            item_id = row['Item ID']
            
            # Scope Increase (Burn-up)
            if row['Change Type'] == 'task add' and item_id in estimates:
                current_sp += estimates[item_id]
            
            # Task Completed (Burn-down)
            elif row['Change Type'] == 'status transition' and row['To State'] == 'Done' and item_id in estimates:
                current_sp -= estimates[item_id]
                
        daily_sp.append(current_sp)

    # 5. Plotting the Chart
    plt.figure(figsize=(10, 6))

    # Actual Remaining SP Line
    plt.plot(date_range, daily_sp, marker='o', linestyle='-', color='blue', linewidth=2, label='Actual Remaining SP')

    # Ideal Burndown Line
    ideal_sp = [initial_sp * (1 - i / (len(date_range) - 1)) for i in range(len(date_range))]
    plt.plot(date_range, ideal_sp, linestyle='--', color='gray', label='Ideal Burndown')

    # Formatting
    plt.title('Sprint Burndown Chart')
    plt.xlabel('Date')
    plt.ylabel('Story Points Remaining')
    plt.ylim(0, max(initial_sp + 5, max(daily_sp) + 2))
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.legend()
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
    plt.xticks(rotation=45)
    plt.tight_layout()

    # Save the file
    output_path = PROJECT_ROOT / output_image_name
    plt.savefig(output_path)

if __name__ == "__main__":
    args = sys.argv[1:]

    if len(args) == 0:
        generate_burndown('S2_SPRINT_BACKLOG.csv', 'S2_SCOPE_CHANGE_LOG.csv', 'sprint2_burndown.png')
        generate_burndown('S1_SPRINT_BACKLOG.csv', 'S1_SCOPE_CHANGE_LOG.csv', 'sprint1_burndown.png')
    elif len(args) == 3:
        generate_burndown(args[0], args[1], args[2])
    else:
        raise SystemExit(
            "Usage: python Sprint_Data/burndown_charts.py [backlog.csv changelog.csv output.png]"
        )