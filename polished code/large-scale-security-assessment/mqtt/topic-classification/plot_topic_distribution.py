# import module
import matplotlib.pyplot as plt

data = {'sensor': 190312, 'update': 198031, 'location': 18606, 'home': 56080, 'transportation': 20684, 'health': 14040, 'identifier': 125723, 'security': 44017, 'industry': 30325}

# Extracting the keys and values
categories = list(data.keys())
values = list(data.values())

# Plotting the histogram
plt.figure(figsize=(10, 6))
bars = plt.bar(categories, values, color='#D5E8D4', edgecolor='#82B366', linewidth=2)

# Adding the values on top of the bars with commas
for bar in bars:
    height = bar.get_height()
    plt.text(bar.get_x() + bar.get_width() / 2.0, height, f'{height:,}', ha='center', va='bottom', fontsize=12)

plt.xticks(range(len(categories)), categories, rotation=0, fontsize=12)

# Adjusting every second label
for i, label in enumerate(plt.gca().get_xticklabels()):
    if i % 2 != 0:
        label.set_y(label.get_position()[1] - 0.03)

plt.yticks(range(0, max(values) + 50000, 50000), [f'{i//1000}k' for i in range(0, max(values) + 50000, 50000)])

# Removing top and right plot borders
plt.gca().spines['top'].set_visible(False)
plt.gca().spines['right'].set_visible(False)

# Setting y-axis to logarithmic scale
# plt.yscale('log')

# plt.tight_layout()
# plt.show()
plt.savefig('mqtt_topic_distribution.pdf', bbox_inches='tight')