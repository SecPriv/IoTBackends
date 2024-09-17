#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import matplotlib, json
import matplotlib.pyplot as plt
import numpy as np

size = 15

matplotlib.rc('font', **{'size': size})

# Dataset
data = json.load(open('aggregated_results.json', 'r'))

categories = ['MQTT Information Leakage', 'MQTT DoS', 'CoAP Information Leakage', 'CoAP DoS']
subcategories = ['information_leakage', 'DoS']
years = [2022, 2023, 2024]

def add_labels(rects, values):
    for rect, value in zip(rects, values):
        height = rect.get_height()
        ax.text(
            rect.get_x() + rect.get_width() / 2.,
            rect.get_y() + height / 2,
            f"{value:,}",  # Format numbers with commas
            ha='center', va='center'
        )

def add_year_label(rects, year):
    for rect, value in zip(rects, values):
        ax.text(
            rect.get_x() + rect.get_width() / 2.,
            -3,
            f"{year}",
            ha='center', va='top'
        )

# Convert data to percentages based on the 2022 value
def to_percentage(values, base_year, year):
    if values[base_year] == 0:
        return 0
    return values[year] * 100.0 / values[base_year]

# Prepare plot
fig, ax = plt.subplots(figsize=(14, 8))

bar_width = 0.275  # Width of each bar
padding = 0.125 / 6
x = np.arange(len(categories))  # Positions for each category

colors = {
    "still_vulnerable": '#DAE8FC',
    "not_vulnerable": '#D5E8D4',
    "offline": '#FFF2CC',
    "new_vulnerable": '#F8CECC'
}

# Plot bars for each category and year
for i, (cat_key, cat_label) in enumerate(zip(['mqtt', 'mqtt', 'coap', 'coap'], categories)):
    subcat_key = subcategories[i % 2]
    values = data[cat_key][subcat_key]

    # Calculate percentages, 2022 is the base year (100%)
    percentages = {
        "2022": 100,  #
        "2023": [
            to_percentage(values, '2022', '2023'),
            to_percentage(values, '2022', 'not_vuln_2023'),
            to_percentage(values, '2022', 'offline_2023'),
            to_percentage(values, '2022', 'new_vuln_2023')
        ],
        "2024": [
            to_percentage(values, '2022', '2024'),
            to_percentage(values, '2022', 'not_vuln_2024'),
            to_percentage(values, '2022', 'offline_2024'),
            to_percentage(values, '2022', 'new_vuln_2024')
        ]
    }

    # Plot 2022 bar
    rect_2022 = ax.bar(x[i] - bar_width - padding, percentages["2022"], bar_width, color=colors["still_vulnerable"], label='Vulnerable' if i == 0 else "", edgecolor='#6C8EBF', linewidth=2)
    add_labels(rect_2022, [values["2022"]])
    add_year_label(rect_2022, 2022)

    # Plot 2023 stacked bars
    rects_2023_1 = ax.bar(x[i], percentages["2023"][0], bar_width, color=colors["still_vulnerable"], edgecolor='#6C8EBF', linewidth=2)
    rects_2023_2 = ax.bar(x[i], percentages["2023"][1], bar_width, bottom=percentages["2023"][0], color=colors["not_vulnerable"], label='No Longer Vulnerable' if i == 0 else "", edgecolor='#82B366', linewidth=2)
    rects_2023_3 = ax.bar(x[i], percentages["2023"][2], bar_width, bottom=sum(percentages["2023"][:2]), color=colors["offline"], label='Offline' if i == 0 else "", edgecolor='#D6B656', linewidth=2)
    rects_2023_4 = ax.bar(x[i], percentages["2023"][3], bar_width, bottom=sum(percentages["2023"][:3]), color=colors["new_vulnerable"], label='Now Vulnerable' if i == 0 else "", edgecolor='#B85450', linewidth=2)

    add_labels(rects_2023_1, [values["2023"]])
    add_labels(rects_2023_2, [values["not_vuln_2023"]])
    add_labels(rects_2023_3, [values["offline_2023"]])
    add_labels(rects_2023_4, [values["new_vuln_2023"]])
    add_year_label(rects_2023_1, 2023)

    # Plot 2024 stacked bars
    rects_2024_1 = ax.bar(x[i] + bar_width + padding, percentages["2024"][0], bar_width, color=colors["still_vulnerable"], edgecolor='#6C8EBF', linewidth=2)
    rects_2024_2 = ax.bar(x[i] + bar_width + padding, percentages["2024"][1], bar_width, bottom=percentages["2024"][0], color=colors["not_vulnerable"], edgecolor='#82B366', linewidth=2)
    rects_2024_3 = ax.bar(x[i] + bar_width + padding, percentages["2024"][2], bar_width, bottom=sum(percentages["2024"][:2]), color=colors["offline"], edgecolor='#D6B656', linewidth=2)
    rects_2024_4 = ax.bar(x[i] + bar_width + padding, percentages["2024"][3], bar_width, bottom=sum(percentages["2024"][:3]), color=colors["new_vulnerable"], edgecolor='#B85450', linewidth=2)

    add_labels(rects_2024_1, [values["2024"]])
    add_labels(rects_2024_2, [values["not_vuln_2024"]])
    add_labels(rects_2024_3, [values["offline_2024"]])
    add_labels(rects_2024_4, [values["new_vuln_2024"]])
    add_year_label(rects_2024_1, 2024)

# Set labels and title
ax.set_xlim(-2 * (bar_width - padding) + padding, max(ax.get_xticks()) - 2 * (bar_width - padding))
ax.set_xticks(x)
ax.set_xticklabels(categories, y=-0.06)
ax.tick_params(axis='x', which='major', length=0)
# ax.set_ylabel("Percentage")
ax.set_ylim(0, 137)
ax.set_yticks(range(0,140,10))
ax.set_yticklabels([f"{y}%" for y in ax.get_yticks()])
ax.yaxis.set_minor_locator(matplotlib.ticker.AutoMinorLocator())
ax.tick_params(axis='y', which='major', length=5, labelsize=15)
ax.tick_params(axis='y', which='minor', length=2, labelsize=8)
# ax.set_title("Vulnerability Trend Over Years")

# Removing top and right plot borders
plt.gca().spines['top'].set_visible(False)
plt.gca().spines['right'].set_visible(False)

# Legend
ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.1), ncol=4, prop={'size': size}, frameon=False)

plt.savefig('vulnerability_trend_overall.pdf', bbox_inches='tight')

# plt.tight_layout()
# plt.show()
