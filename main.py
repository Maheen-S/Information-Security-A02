import pandas as pd
import matplotlib.pyplot as plt
from sklearn.utils import resample
from imblearn.over_sampling import SMOTE
import random
import string
import seaborn as sns
import re
from sklearn.feature_extraction.text import TfidfVectorizer

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

    plt.savefig('class_distribution.png') 
    plt.show()

def generate_random_url(label_type):
    """
    Generate a random URL based on the label type.
    """
    domains = ['.com', '.net', '.org', '.biz', '.info']
    protocols = ['http://', 'https://']
    random_url = random.choice(protocols) + ''.join(random.choices(string.ascii_lowercase + string.digits, k=10)) + random.choice(domains)
    return random_url


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

    # Generate synthetic URLs for the new samples
    synthetic_urls = [generate_random_url(label) for label in smote_labels]

    # Create DataFrame of generated URLs
    smote_generated = pd.DataFrame({'url': synthetic_urls, 'type': smote_labels})
    smote_generated['label'] = smote_generated['type'].map({'malware': 3, 'spam': 4})

    # Combine all original data along with the generated samples
    balanced_data = pd.concat([
        benign_downsampled, 
        defacement_data, 
        phishing_data, 
        malware_data, 
        spam_data, 
        smote_generated
    ], ignore_index=True)

    # Save the balanced dataset to a CSV file
    balanced_data.to_csv(balanced_data_out, index=False)
    print(f"Balanced dataset saved successfully at {balanced_data_out}")

def visualize_url_length_distribution(balanced_data):
    """
    Plot the distribution of URL lengths by label type.
    """
    balanced_data['url_length'] = balanced_data['url'].apply(len)
    plt.figure(figsize=(12, 6))
    sns.histplot(data=balanced_data, x='url_length', hue='type', element='step', bins=50, palette='Set2')
    plt.title('Distribution of URL Lengths by Label')
    plt.xlabel('URL Length')
    plt.ylabel('Frequency')
    plt.savefig('url_length_distribution.png') 
    plt.show()

def generate_descriptive_statistics(balanced_data):
    """
    Generate and display descriptive statistics of the dataset.
    """
    descriptive_stats = balanced_data.describe(include='all')
    print(descriptive_stats)

def url_structure_analysis(balanced_data):
    """
    Perform URL structure analysis and display the number of URLs containing 'https' for each label.
    Also, identify malicious patterns in URLs.
    """
    # Checking for presence of 'https'
    balanced_data['contains_https'] = balanced_data['url'].apply(lambda x: 'https' in x)

    # Checking for IP addresses in URLs
    balanced_data['contains_ip'] = balanced_data['url'].apply(lambda x: bool(re.search(r'\d+\.\d+\.\d+\.\d+', x)))

    # Checking for suspicious keywords in URLs
    keywords = ['login', 'verify', 'click', 'free', 'password', 'account', 'update']
    balanced_data['contains_suspicious_keyword'] = balanced_data['url'].apply(lambda x: any(keyword in x.lower() for keyword in keywords))

    # Generate token summary
    token_summary = balanced_data.groupby(['type', 'contains_https', 'contains_ip', 'contains_suspicious_keyword']).size().reset_index(name='Count')

    # Displaying results
    print(token_summary)

#######################################################################################################################

def structural_feature_extraction(balanced_data):
    """
    Extract structural features from URLs.
    """
    balanced_data['url_length'] = balanced_data['url'].apply(len)
    balanced_data['num_digits'] = balanced_data['url'].apply(lambda x: sum(c.isdigit() for c in x))
    balanced_data['num_subdomains'] = balanced_data['url'].apply(lambda x: x.count('.'))
    balanced_data['num_special_chars'] = balanced_data['url'].apply(lambda x: len(re.findall(r'[^a-zA-Z0-9]', x)))

    print("Structural Features Extracted Successfully!")
    return balanced_data


def tfidf_vectorization(balanced_data):
    """
    Apply TF-IDF vectorization to URLs.
    """
    vectorizer = TfidfVectorizer(analyzer='char', ngram_range=(3, 5))
    tfidf_features = vectorizer.fit_transform(balanced_data['url'])

    print("TF-IDF Vectorization Applied Successfully!")
    return tfidf_features, vectorizer


#FOR VISUALIZATIONS
def class_distribution_plot(balanced_data):
    """
    Plot the distribution of classes after balancing.
    """
    plt.figure(figsize=(10, 6))
    sns.countplot(x='type', data=balanced_data, palette='viridis')
    plt.title('Class Distribution After Balancing')
    plt.xlabel('Class Labels')
    plt.ylabel('Number of Samples')
    plt.savefig('class_distribution.png') 
    plt.show()

def visualize_special_char_count(balanced_data):
    """
    Plot the distribution of special character counts by label type.
    """
    balanced_data['special_char_count'] = balanced_data['url'].apply(lambda x: len(re.findall(r'[^a-zA-Z0-9]', x)))

    plt.figure(figsize=(12, 6))
    sns.histplot(data=balanced_data, x='special_char_count', hue='type', bins=30, kde=True, palette='Set2')
    plt.title('Special Character Count Distribution Across Classes')
    plt.xlabel('Special Character Count')
    plt.ylabel('Frequency')
    plt.savefig('special_char_count.png') 
    plt.show()

def plot_correlation_heatmap(balanced_data):
    """
    Plot correlation heatmap of structural features.
    """
    structural_features = ['url_length', 'num_digits', 'num_subdomains', 'num_special_chars']
    correlation_matrix = balanced_data[structural_features].corr()

    plt.figure(figsize=(8, 6))
    sns.heatmap(correlation_matrix, annot=True, cmap='coolwarm')
    plt.title('Correlation Heatmap of Structural Features')
    plt.savefig('correlation_heatmap.png') 
    plt.show()

def improved_url_length_distribution(balanced_data):
    """
    Plot the URL length distribution across different classes.
    """
    plt.figure(figsize=(12, 6))
    sns.histplot(data=balanced_data, x='url_length', hue='type', element='step', bins=50, palette='tab10', kde=True)
    plt.title('URL Length Distribution Across Classes')
    plt.xlabel('URL Length')
    plt.ylabel('Frequency')
    plt.savefig('length_distribution.png') 
    plt.show()

def keyword_presence_analysis(balanced_data):
    """
    Plot keyword presence analysis across classes.
    """
    keyword_counts = balanced_data.groupby(['type', 'contains_suspicious_keyword']).size().reset_index(name='Count')
    
    plt.figure(figsize=(10, 6))
    sns.barplot(data=keyword_counts, x='type', y='Count', hue='contains_suspicious_keyword', palette='viridis')
    plt.title('Keyword Presence Analysis Across Classes')
    plt.xlabel('URL Type')
    plt.ylabel('Count')
    plt.legend(title='Contains Suspicious Keyword', labels=['No', 'Yes'])
    plt.savefig('keyword_presense_analysis.png') 
    plt.show()


if __name__ == "__main__":
    # File paths
    malicious_file = "malicious_phish.csv"
    spam_file = "spam_dataset.csv"
    output_file = "combined_dataset.csv"
    clean_data = "final_data.csv"
    balanced_data = "balanced_data.csv"

    # step 01: Combining datasets
    # combine_datasets(malicious_file, spam_file, output_file)

    # Read combined dataset csv
    # combine_datasets = pd.read_csv(output_file)
    # print(len(combine_datasets))

    ########################

    # step 2 : preprocess datasets
    # preprocess_datasets(combine_datasets, clean_data)

    # Read preprocessed dataset csv
    # preprocess_datasets = pd.read_csv(clean_data)
    # print(len(preprocess_datasets))

    # class_imbalance_analysis(preprocess_datasets)
    
    ########################

    # step 3
    # balance_datasets(preprocess_datasets, balanced_data)

    # # Read balance_datasetst csv
    final_balanaced = pd.read_csv(balanced_data)
    # print(len(final_balanaced))

    # class_imbalance_analysis(final_balanaced)
        
    ########################

    # step 4: EDA
    visualize_url_length_distribution(final_balanaced)
    generate_descriptive_statistics(final_balanaced)
    url_structure_analysis(final_balanaced)


    # step 6: 
    final_balanaced = structural_feature_extraction(final_balanaced)
    tfidf_features, vectorizer = tfidf_vectorization(final_balanaced)

    # Save structural features to CSV for further use
    final_balanaced.to_csv('balanced_data_with_features.csv', index=False)
    print("Structural Features saved successfully to balanced_data_with_features.csv")



    # CLASS BALANCING DONE, balanced_data.csv IS OUR FINAL FILE NOW 


    # Step 5: Generate Graphs and Plots
    class_distribution_plot(final_balanaced)
    visualize_special_char_count(final_balanaced)
    plot_correlation_heatmap(final_balanaced)
    improved_url_length_distribution(final_balanaced)
    keyword_presence_analysis(final_balanaced)


