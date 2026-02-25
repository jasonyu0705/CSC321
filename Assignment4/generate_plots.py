import matplotlib.pyplot as plt

# Data supplied by the user
data = [
    (8, 25, 0.000199),
    (10, 21, 0.000122),
    (12, 81, 0.000441),
    (14, 198, 0.001050),
    (16, 71, 0.000362),
    (18, 741, 0.004918),
    (20, 1047, 0.007115),
    (22, 1745, 0.009069),
    (24, 5418, 0.029401),
    (20, 1047, 0.007115),
    (22, 1745, 0.009069),
    (20, 1047, 0.007115),
    (22, 1745, 0.009069),
    (20, 1047, 0.007115),
    (22, 1745, 0.009069),
    (20, 1047, 0.007115),
    (20, 1047, 0.007115),
    (20, 1047, 0.007115),
    (22, 1745, 0.009069),
    (24, 5418, 0.029401),
    (26, 8813, 0.047050),
    (28, 9882, 0.100048),
    (30, 37533, 0.199138),
    (32, 87153, 0.467167),
    (34, 326610, 1.917706),
    (36, 840566, 5.227642),
    (38, 463783, 3.331098),
    (40, 1393169, 8.044700),
    (42, 1466996, 8.574606),
    (44, 8555873, 90.073811),
    (46, 11196686, 72.918364),
    (48, 17925117, 115.683658),
    (50, 59459645, 363.595318)
]

# Separate data into lists
# Filter out duplicates by using a dictionary (keeping the last occurrence or just unique set)
# Given the user pasted raw data, I'll filter to unique (bits, inputs, time) tuples to clean up the plot
unique_data = sorted(list(set(data)), key=lambda x: x[0])

bits = [x[0] for x in unique_data]
inputs = [x[1] for x in unique_data]
times = [x[2] for x in unique_data]

# Plot 1: Digest Size vs Collision Time
plt.figure(figsize=(10, 6))
plt.plot(bits, times, marker='o', linestyle='-', color='b')
plt.title("Digest Size vs. Collision Time")
plt.xlabel("Digest Size (Bits)")
plt.ylabel("Time (Seconds)")
plt.grid(True)
plt.savefig("Digest_Size_vs_Time.png")
# plt.show()

# Plot 2: Digest Size vs Number of Inputs
plt.figure(figsize=(10, 6))

plt.plot(bits, inputs, marker='s', linestyle='-', color='r')
plt.title("Digest Size vs. Number of Inputs")
plt.xlabel("Digest Size (Bits)")
plt.ylabel("Number of Inputs to Find Collision")
plt.grid(True)
plt.yscale('log') # Log scale is often useful for measuring collision inputs (exponential growth)
plt.savefig("Digest_Size_vs_Inputs.png")
# plt.show()

print("Plots generated: 'Digest_Size_vs_Time.png' and 'Digest_Size_vs_Inputs.png'")
