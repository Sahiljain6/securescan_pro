from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB

vectorizer = CountVectorizer()

X = vectorizer.fit_transform([
    "select * from users",
    "' OR '1'='1",
    "normal text",
    "<script>alert(1)</script>"
])

y = [1, 1, 0, 1]

model = MultinomialNB()
model.fit(X, y)

def predict_input(text):
    prediction = model.predict(vectorizer.transform([text]))[0]
    return "⚠ Suspicious Input" if prediction == 1 else "✔ Normal Input"
