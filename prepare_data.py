#For this module of code to work, the datasets are downloaded off https://github.com/Jehuty4949/NSL_KDD
#Files KDDTrain+.arff and KDDTest+.arff are placed into same folder as this code
#If computer doesnt have any imports loaded, thonny -> tools -> Open system shell -> enter: pip install pandas, pip install scikit-learn, pip install joblib, pip install scipy
import os
import pandas as pd
import numpy as np
from scipy.io import arff
from sklearn.preprocessing import MinMaxScaler
from sklearn.model_selection import train_test_split

#Feature Mapping -
#NSL-KDD dataset has 41 named feature
#Only the 7 features we need are used

FEATURE_MAP = {
    "packet_count": "count",
    "avg_packet_count": "src_bytes",
    "duration": "duration",
    "failed_logins": "num_failed_logins",
    "requests_per_sec": "dst_bytes",
    "unusal_port": "land",
    "data_volume": "dst_bytes"
    }

#These are the NSL-KDD names we are using
NSL_KDD_SELECTED = ["count", "src_bytes", "duration", "num_failed_logins", "dst_bytes", "land"]

#These are all 41 feature names in NSL-KDD
NSL_KDD_ALL_COLUMNS = ["duration","protocol_type","service","flag","src_bytes","dst_bytes","land","wrong_fragment","urgent","hot",
                       "num_failed_logins","logged_in","num_compromised","root_shell","su_attempted","num_root","num_file_creations",
                       "num_shells","num_access_files","num_outbound_cmds","is_host_login","is_guest_login","count","srv_count","serror_rate",
                       "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate","diff_srv_rate","srv_diff_host_rate","dst_host_count",
                       "dst_host_srv_count","dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate","dst_host_srv_diff_host_rate",
                       "dst_host_serror_rate","dst_host_srv_serror_rate","dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"
]

#This loads an arff file and returns it as Panda DataFrame
def load_arff_file(filepath):
    print(f"Loading {filepath}...")
    data, _=arff.loadarff(filepath) #returns metadata
    df = pd.DataFrame(data)
    for col in df.select_dtypes(include=["object"]).columns: #This decodes the arff files from byte strings
        df[col] =df[col].str.decode("utf-8")
    return df

#This is an alternative loader if user has CSV version of NSL-KDD
def load_csv_file(filepath):
    print(f"Loading {filepath} as CSV...")
    df = pd.read_csv(filepath, header=None, names=NSL_KDD_ALL_COLUMNS) # CSV verison doesnt have column headers so we need at assign them ourselves
    return df

#This generates sythetic NSL-KDD data for tarining and testing
def generate_synthetic_data(n_samples=5000):
    print("Generating synthetic NSL-KDD style data for development...")
    np.random.seed(42) #Fixed seed so results and repeatable
    n_normal = int(n_samples*0.6) #60% is normal traffic
    n_attack = n_samples - n_normal #Rest is 40% attack traffic
    #Normal traffic features
    normal = {
        "count": np.random.randint(1, 50, n_normal),
        "src_bytes": np.random.randint(0, 5000, n_normal),
        "duration": np.random.randint(0, 100, n_normal),
        "num_failed_logins": np.zeros(n_normal, dtype=int),
        "dst_bytes": np.random.randint(0, 8000, n_normal),
        "land": np.zeros(n_normal, dtype=int),
        "label": np.zeros(n_normal, dtype=int) # 0 = normal
        }
    #Attack traffic features
    attack = {
        "count": np.random.randint(200, 512, n_attack),
        "src_bytes": np.random.randint(5000, 50000, n_attack),
        "duration": np.random.randint(0, 5, n_attack),
        "num_failed_logins": np.random.randint(1, 10, n_attack),
        "dst_bytes": np.random.randint(0, 500, n_attack),
        "land": np.random.randint(0, 2, n_attack),
        "label": np.ones(n_attack, dtype=int) # 1 = attack
        }
    #Combines both attack and normal traffic into 1 dataframe and shuffles them
    df_normal = pd.DataFrame(normal)
    df_attack = pd.DataFrame(attack)
    df = pd.concat([df_normal, df_attack], ignore_index= True)
    df = df.sample(frac= 1, random_state= 42).reset_index(drop=True) #This shuffles dataframe
    return df

#Each row within NSL-KDD is labelled as a specific attack type
#For logistic regression binary classification we need 0 = normal traffic , 1 = any attack
#This converts the labels to binary (0/1)
def convert_labels_to_binary(df):
    print("Converting multi-class labels into binary (0 = normal, 1 = attack)...")
    df["label"] = df["label"].apply(lambda x: 0 if str(x).strip().lower() == "normal" else 1)
    return df

#Extracts the 7 features we chose to use from the 41 column dataset
#Renames them to my design names so the rest of codebase uses more readable names
def select_and_rename_features(df):
    print("Selecting + renaming features...")
    cols_to_keep = NSL_KDD_SELECTED + ["label"] #Keeps only the useful columns and the label
    cols_to_keep = list(dict.fromkeys(cols_to_keep)) #Gets rid of any duplicates
    df = df[cols_to_keep].copy() #Gets rid of any duplicates
    #Renaming to my design names
    rename_map = {
        "count": "packet_count",
        "src_bytes": "avg_packet_size",
        "duration": "duration",
        "num_failed_logins": "failed_logins",
        "dst_bytes": "data_volume",
        "land": "unusual_port"
        }
    df = df.rename(columns=rename_map)
    df["requests_per_sec"] = df["packet_count"] / df["duration"].clip(lower=1) #Adds requests_per_sec as a feature, makes sure it cant be divided by 0 
    return df

#This cleans dataset before training:
#Removes null values, converts all feature columns to numeric and resets index after dropping rows
def clean_data(df):
    print("CLeaning data (removing null values, converting types)...")
    original_len = len(df)
    #Coverts all non-label columns to numeric and replaces erros with NaN(Not a number)
    feature_cols = [c for c in df.columns if c != "label"]
    for col in feature_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce")
    df = df.dropna().reset_index(drop=True) #Drops rows with NaN after conversion
    removed = original_len - len(df)
    print(f"Removed {removed} rows with null values. {len(df)} rows remain")
    return df

#Uses MinMax normalisation to all feature columns, scaling them into range of 0, 1 so features with larger values dont have priority over features with smaller values
def normalise_features(df, scaler=None):
    print("Normalising features using Min-Max scaling...")
    feature_cols = [c for c in df.columns if c != "label"]
    if scaler is None: #Training time - fit scaler on trainin data
        scaler = MinMaxScaler()
        df[feature_cols] = scaler.fit_transform(df[feature_cols])
    else: #Test time: use the default scaler
        df[feature_cols] = scaler.transform(df[feature_cols])
    return df, scaler

#This saves min-max value for each feature to CSV file
def save_scaler_params(scaler, feature_cols, output_path):
    print(f"Saving scaler values to {output_path}...")
    params = pd.DataFrame({
        "feature": feature_cols,
        "min": scaler.data_min_,
        "max": scaler.data_max_
        })
    params.to_csv(output_path, index=False)
    
#This is the main function the controls the full data preparation. Loads real NSL-KDD files first, has access to synthetic incase they arent found
def main():
    print("AI IDS Data Preparation Module")
    print("=" * 60)
    os.makedirs("data", exist_ok=True) #This is the output directory
    
    #Loading raw data, finding real NSL-KDD files in computer
    train_arff = "KDDTrain+.arff"
    train_csv  = "KDDTrain+.txt"
    if os.path.exists(train_arff):
        print("\n[1/5] Found KDDTrain+.arff - Loading real NSL-KDD dataset")
        df = load_arff_file(train_arff)
        df = convert_labels_to_binary(df)
        df = select_and_rename_features(df)
    elif os.path.exists(train_csv):
        print("\n[1/5] Found KDDTrain+.txt - Loading real NSL-KDD dataset")
        df = load_csv_file(train_csv)
        df = convert_labels_to_binary(df)
        df = select_and_rename_features(df)
    else:
        print("NSL-KDD files not found - Switched to using synthetic data")
        print("(Download KDDTrain.arff from https://www.unb.ca/cic/datasets/nsl.html)")
        print("(Place into same folder as these scripts (not the data folder), then retry)")
        df = generate_synthetic_data(n_samples=8000)
        df = select_and_rename_features(df) #Synthetic data uses NSL-KDD column names so use the same rename function
    
    #Clean data
    print("\n[2/5] Cleaning data")
    df = clean_data(df)
    #print an overview of dataset balance
    label_counts = df["label"].value_counts()
    print(f"Normal traffic: {label_counts.get(0,0)} rows")
    print(f"Attack traffic: {label_counts.get(1,0)} rows")
    
    #Split data into training (80%) and testing (20%) sets
    print("\n[3/5] Splitting data into training (80%) and testing (20%) sets")
    feature_cols = [c for c in df.columns if c != "label"]
    x =df[feature_cols] #Features (inputs)
    y = df["label"] #labels (predictions)
    #Ensuring both splits have same ratio of normal:attack
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size = 0.2, random_state = 42, stratify = y)
    print(f"Training set: {len(x_train)} rows")
    print(f"Test set: {len(x_test)} rows")
    
    #Normalising features
    print("\n[4/5] Normalising features")
    #temporarily combine x and y into DataFrame for to save them easier
    train_df = x_train.copy()
    train_df["label"] = y_train.values
    test_df = x_test.copy()
    test_df["label"] = y_test.values
    #Fit scaler on training data first, then apply it to test data
    train_df, scaler = normalise_features(train_df, scaler=None)
    test_df,  _      =normalise_features(test_df, scaler=scaler)
    
    #Save outputs
    print("\n[5/5] Saving processed files to folder")
    train_df.to_csv("data/train_clean.csv", index=False)
    print("Saved: data/train_clean.csv")
    test_df.to_csv("data/test_clean.csv", index=False)
    print("Saved: data/test_clean.csv")
    save_scaler_params(scaler, feature_cols, "data/scaler_params.csv")
    print("Saved: data/scaler_parameters.csv")
    print()
    print("Data preparation is complete")
    print("Next run model.py to train AI model")
if __name__ == "__main__":
    main()

        
        
        
    
    
    
                    