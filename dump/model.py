import pandas as pd
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import nltk
import string
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer

# Download required NLTK packages
nltk.download('punkt')
nltk.download('stopwords')
nltk.download('wordnet', download_dir='/root/nltk_data/')  # Required for WordNetLemmatizer

# Load the data
data = pd.read_csv('/home/carbon/COMSNETS/file_data_v3.csv')
data_benign = pd.read_csv('/home/carbon/COMSNETS/benign_data_withreadme_v2.csv')

# Combine data
combined_df = pd.concat([data, data_benign], ignore_index=True)
print("done")
print(combined_df.tail())

# Convert labels to binary (1 for ransomware, 0 for benign)
combined_df['label'] = combined_df['label'].apply(lambda x: 1 if x == 'ransom' else 0)
print("DONE")

# Text Preprocessing function
def preprocess_text(text):
    if isinstance(text, str):
        # Tokenization
        tokens = nltk.word_tokenize(text.lower())

        # Punctuation removal
        translator = str.maketrans('', '', string.punctuation)
        tokens = [token.translate(translator) for token in tokens]

        # Stop word removal
        stop_words = set(stopwords.words('english'))
        tokens = [token for token in tokens if token not in stop_words]

        # Lemmatization
        lemmatizer = WordNetLemmatizer()
        tokens = [lemmatizer.lemmatize(token) for token in tokens]

        return tokens
    else:
        return []

# Apply preprocessing
combined_df['processed_content'] = combined_df['contents'].apply(preprocess_text)
combined_df['joined_tokens'] = combined_df['processed_content'].apply(lambda x: ' '.join(x))

# Feature Preparation - TF-IDF
vectorizer_tfidf = TfidfVectorizer(max_features=1000, min_df=10)
X_tfidf = vectorizer_tfidf.fit_transform(combined_df['joined_tokens'])

# Chi-Squared Feature Selection
selector = SelectKBest(chi2, k=400)
X_chi2 = selector.fit_transform(X_tfidf, combined_df['label'])

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X_chi2, combined_df['label'], test_size=0.3, random_state=42)

# Random Forest Classifier
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

# Predictions
y_pred = rf_model.predict(X_test)
print("Accuracy (Chi-Squared):", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred))
# print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

# Additional Metrics
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

y_true = combined_df['label']
y_pred_all = rf_model.predict(X_chi2)  # Predict using all data

print("Accuracy:", accuracy_score(y_true, y_pred_all))
print("Precision:", precision_score(y_true, y_pred_all))
print("Recall:", recall_score(y_true, y_pred_all))
print("F1-Score:", f1_score(y_true, y_pred_all))
print("Confusion Matrix:\n", confusion_matrix(y_true, y_pred_all))

# --- Print misclassified notes ---
# Get misclassified indices
misclassified_indices = combined_df.index[y_true != y_pred_all]

# Print the misclassified notes
for index in misclassified_indices:
    true_label = 'Ransomware' if y_true[index] == 1 else 'Benign'
    predicted_label = 'Ransomware' if y_pred_all[index] == 1 else 'Benign'
    content = combined_df['contents'][index]

    print(f"\nMisclassified Note at Index {index}:")
    print(f"True Label: {true_label}, Predicted Label: {predicted_label}")
    print(f"Content:\n{content}\n")

with open('model.pkl', 'wb') as f:
    pickle.dump((vectorizer_tfidf, selector, rf_model), f)
