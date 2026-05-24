import random
import pandas as pd
import joblib

from deap import base, creator, tools
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

# =========================
# Load Dataset
# =========================

file_path = r"C:\Users\M\Desktop\EvoGuard-Enterprise\data\raw\nsl_kdd_train.txt"

columns = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "label", "difficulty_level"
]

df = pd.read_csv(file_path, names=columns)
df = df.drop("difficulty_level", axis=1)

# =========================
# Encode Text Columns
# =========================

label_encoders = joblib.load("label_encoders.pkl")

for col in ["protocol_type", "service", "flag", "label"]:
    df[col] = label_encoders[col].transform(df[col])

X = df.drop("label", axis=1)
y = df["label"]

feature_names = list(X.columns)
num_features = len(feature_names)

# Use smaller sample for faster GA
X_sample, _, y_sample, _ = train_test_split(
    X, y, train_size=0.25, random_state=42, stratify=y
)

X_train, X_test, y_train, y_test = train_test_split(
    X_sample, y_sample, test_size=0.2, random_state=42
)

# =========================
# Genetic Algorithm Setup
# =========================

creator.create("FitnessMax", base.Fitness, weights=(1.0,))
creator.create("Individual", list, fitness=creator.FitnessMax)

toolbox = base.Toolbox()

toolbox.register("attr_bool", random.randint, 0, 1)
toolbox.register(
    "individual",
    tools.initRepeat,
    creator.Individual,
    toolbox.attr_bool,
    n=num_features
)
toolbox.register("population", tools.initRepeat, list, toolbox.individual)


def evaluate(individual):
    selected_features = [
        feature_names[i]
        for i in range(num_features)
        if individual[i] == 1
    ]

    if len(selected_features) == 0:
        return 0,

    model = RandomForestClassifier(
        n_estimators=40,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train[selected_features], y_train)
    predictions = model.predict(X_test[selected_features])
    accuracy = accuracy_score(y_test, predictions)

    return accuracy,


toolbox.register("evaluate", evaluate)
toolbox.register("mate", tools.cxTwoPoint)
toolbox.register("mutate", tools.mutFlipBit, indpb=0.05)
toolbox.register("select", tools.selTournament, tournsize=3)

# =========================
# Run GA
# =========================

population = toolbox.population(n=10)
generations = 8

best_scores = []

print("\nEvoGuard Genetic Algorithm Started...\n")

for gen in range(generations):
    offspring = toolbox.select(population, len(population))
    offspring = list(map(toolbox.clone, offspring))

    for child1, child2 in zip(offspring[::2], offspring[1::2]):
        if random.random() < 0.7:
            toolbox.mate(child1, child2)
            del child1.fitness.values
            del child2.fitness.values

    for mutant in offspring:
        if random.random() < 0.2:
            toolbox.mutate(mutant)
            del mutant.fitness.values

    invalid_individuals = [
        ind for ind in offspring if not ind.fitness.valid
    ]

    fitnesses = map(toolbox.evaluate, invalid_individuals)

    for ind, fit in zip(invalid_individuals, fitnesses):
        ind.fitness.values = fit

    population[:] = offspring

    best_individual = tools.selBest(population, 1)[0]
    best_accuracy = best_individual.fitness.values[0]
    best_scores.append(best_accuracy)

    print(f"Generation {gen + 1}: Best Accuracy = {best_accuracy * 100:.2f}%")

# =========================
# Save Best Features
# =========================

best_individual = tools.selBest(population, 1)[0]

selected_features = [
    feature_names[i]
    for i in range(num_features)
    if best_individual[i] == 1
]

print("\nBest Selected Features:")
for feature in selected_features:
    print("-", feature)

print(f"\nTotal Selected Features: {len(selected_features)} out of {num_features}")

joblib.dump(selected_features, "selected_features.pkl")
joblib.dump(best_scores, "ga_evolution_scores.pkl")

print("\nGenetic Algorithm optimization completed successfully!")
print("Selected features saved.")