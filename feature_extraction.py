import re
from sklearn.base import BaseEstimator, TransformerMixin

class SuspiciousFeatures(BaseEstimator, TransformerMixin):
    def __init__(self, keywords=None):
        self.keywords = keywords or ['password', 'verify', 'login', 'bank', 'urgent']
    def fit(self, X, y=None):
        return self
    def transform(self, X):
        features = []
        url_pattern = re.compile(r'https?://')
        for text in X:
            urls = len(url_pattern.findall(text))
            kw_count = sum(text.lower().count(w) for w in self.keywords)
            features.append([urls, kw_count])
        return features