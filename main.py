import pandas as pd
import matplotlib.pyplot as plt
from sklearn.utils import resample
from imblearn.over_sampling import SMOTE

def combine_datasets(malicious_file, spam_file, output_file):
    # Load the datasets
    malicious_phish = pd.read_csv(malicious_file)
    spam_dataset = pd.read_csv(spam_file, header=None, names=["url"])

    # Add a label column for the spam dataset
    spam_dataset['type'] = 'spam'

    # Merge the datasets
    combined_dataset = pd.concat([malicious_phish, spam_dataset], ignore_index=True)

    # Save the combined dataset to a CSV file
    combined_dataset.to_csv(output_file, index=False)
    print(f"Combined dataset saved successfully at {output_file}")

def preprocess_datasets(combined_dataset, clean_data):
    # Step 1: Handling Missing Values : Checking for missing values and removing rows with missing data if any
    combined_dataset = combined_dataset.dropna()
    print(len(combined_dataset))

    # Step 2: Data Cleaning : Removing duplicate entries if any
    combined_dataset = combined_dataset.drop_duplicates()
    print(len(combined_dataset))

    # Step 3: Encoding Categorical Variables : Encoding the 'type' column to numerical labels for ML models
    # 'phishing': 0, 'benign': 1, 'defacement': 2, 'malware': 3, 'spam': 4
    label_mapping = {label: idx for idx, label in enumerate(combined_dataset['type'].unique())}
    combined_dataset['label'] = combined_dataset['type'].map(label_mapping)

    # Save the cleaned-labeled dataset to a CSV file
    combined_dataset.to_csv(clean_data, index=False)
    print(f"Clean Encoded dataset saved successfully at {output_file}")

    # Display the label mapping for reference
    label_mapping

def class_imbalance_analysis(final_data):
    # Count the number of samples in each category
    label_counts = final_data['type'].value_counts().reset_index()
    label_counts.columns = ['Type', 'Count']    

    plt.figure(figsize=(10, 6))
    plt.bar(label_counts['Type'], label_counts['Count'])
    plt.title('Class Distribution in the Final Dataset')
    plt.xlabel('URL Type')
    plt.ylabel('Count')
    plt.xticks(rotation=45)

    plt.savefig('class_distribution_bal.png') 
    plt.show()

    
def balance_datasets(preprocess_datasets, balanced_data_out):
    # Step 1: Balancing the dataset

    # Separate the majority and minority classes
    benign_data = preprocess_datasets[preprocess_datasets['type'] == 'benign']
    defacement_data = preprocess_datasets[preprocess_datasets['type'] == 'defacement']
    phishing_data = preprocess_datasets[preprocess_datasets['type'] == 'phishing']
    malware_data = preprocess_datasets[preprocess_datasets['type'] == 'malware']
    spam_data = preprocess_datasets[preprocess_datasets['type'] == 'spam']

    # Undersample the benign data
    benign_downsampled = resample(benign_data, 
                                  replace=False,
                                  n_samples=100000,
                                  random_state=42)

    # Combine all the minority data for SMOTE
    minority_data = pd.concat([malware_data, spam_data])

    # Applying SMOTE directly using label column
    smote = SMOTE(sampling_strategy={'malware': 95000, 'spam': 95000}, random_state=42)
    smote_features, smote_labels = smote.fit_resample(minority_data[['label']], minority_data['type'])

    # Create a new dataframe from the generated samples
    smote_generated = pd.DataFrame({'url': ['Generated URL']*len(smote_labels), 'type': smote_labels})

    # Combine all the datasets
    balanced_data = pd.concat([benign_downsampled, defacement_data, phishing_data, smote_generated], ignore_index=True)

    # Save the balanced dataset to a CSV file
    balanced_data.to_csv(balanced_data_out, index=False)
    print(f"Balanced dataset saved successfully at {balanced_data_out}")



if __name__ == "__main__":
    # File paths
    malicious_file = "malicious_phish.csv"
    spam_file = "spam_dataset.csv"
    output_file = "combined_dataset.csv"
    clean_data = "final_data.csv"
    balanced_data = "balanced_data.csv"

    # Combining datasets
    # combine_datasets(malicious_file, spam_file, output_file)

    # Read combined dataset csv
    # combine_datasets = pd.read_csv(output_file)
    # print(len(combine_datasets))

    # # preprocess datasets
    # preprocess_datasets(combine_datasets, clean_data)

    # Read preprocessed dataset csv
    # preprocess_datasets = pd.read_csv(clean_data)
    # print(len(preprocess_datasets))

    # class_imbalance_analysis(preprocess_datasets)

    # balance_datasets(preprocess_datasets, balanced_data)

    # Read balance_datasetst csv
    final_balanaced = pd.read_csv(balanced_data)
    print(len(final_balanaced))

    class_imbalance_analysis(final_balanaced)


    # CLASS BALANCING DONE, balanced_data.csv IS OUR FINAL FILE NOW 




