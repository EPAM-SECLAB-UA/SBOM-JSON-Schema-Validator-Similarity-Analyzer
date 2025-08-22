#!/usr/bin/env python3
"""
SBOM Validator
=================

Overview

A practical tool for validating and analyzing Software Bill of Materials (SBOM) files. This project demonstrates two approaches to solve the same problem, showcasing adaptability and technical depth.
Dual Implementation Strategy

1) Basic Approach
- Uses standard Python libraries only
- Fast, lightweight, and reliable
- Perfect for CI/CD pipelines and resource-constrained environments
- Implements core validation with minimal dependencies

2) Data Analytics Approach
- Leverages pandas, numpy, and scikit-learn
- Provides statistical analysis and machine learning insights
- Advanced anomaly detection and data quality scoring
- Ideal for enterprise environments requiring deep analysis

Author: Vitalii Shevchuk
Date: August 2025
"""

import json
import jsonschema
import time
from collections import Counter
from typing import Dict, List, Any

# Try to import data analytics libraries, fall back to basic functionality if not available
try:
    import pandas as pd
    import numpy as np
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    DATA_ANALYTICS_MODE = True
    print("✅ Data analytics libraries loaded (pandas, numpy, scikit-learn)")
except ImportError:
    DATA_ANALYTICS_MODE = False
    print("⚠️ Running in basic mode (install pandas, numpy, scikit-learn for data analytics features)")

# Simple SBOM schema definition
SBOM_SCHEMA = {
    "type": "object",
    "required": ["project", "components"],
    "properties": {
        "project": {
            "type": "object",
            "required": ["name", "version"],
            "properties": {
                "name": {"type": "string", "minLength": 1},
                "version": {"type": "string"},
                "description": {"type": "string"},
                "category": {"type": "string", "enum": ["web", "mobile", "api", "library", "tool"]}
            }
        },
        "components": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["name", "version", "type"],
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "version": {"type": "string"},
                    "type": {"type": "string", "enum": ["library", "framework", "service", "database", "tool"]},
                    "license": {"type": "string"},
                    "popularity_score": {"type": "number", "minimum": 0, "maximum": 100},
                    "security": {
                        "type": "object",
                        "properties": {
                            "vulnerabilities": {"type": "array"},
                            "risk_score": {"type": "number", "minimum": 0, "maximum": 10}
                        }
                    }
                }
            }
        }
    }
}

# Test examples
WEB_APP_SBOM = {
    "project": {
        "name": "my-web-app",
        "version": "1.0.0",
        "description": "A simple web application",
        "category": "web"
    },
    "components": [
        {
            "name": "react",
            "version": "18.2.0",
            "type": "library",
            "license": "MIT",
            "popularity_score": 95.5,
            "security": {
                "vulnerabilities": [],
                "risk_score": 1.2
            }
        },
        {
            "name": "express",
            "version": "4.18.2",
            "type": "framework",
            "license": "MIT",
            "popularity_score": 89.3,
            "security": {
                "vulnerabilities": ["CVE-2024-12345"],
                "risk_score": 3.8
            }
        }
    ]
}

API_SERVICE_SBOM = {
    "project": {
        "name": "payment-api",
        "version": "2.1.0",
        "description": "Payment processing API",
        "category": "api"
    },
    "components": [
        {
            "name": "fastapi",
            "version": "0.104.1",
            "type": "framework",
            "license": "MIT",
            "popularity_score": 78.9,
            "security": {
                "vulnerabilities": [],
                "risk_score": 1.5
            }
        },
        {
            "name": "postgresql",
            "version": "15.4",
            "type": "database",
            "license": "PostgreSQL",
            "popularity_score": 82.1,
            "security": {
                "vulnerabilities": ["CVE-2024-67890"],
                "risk_score": 5.2
            }
        }
    ]
}

BROKEN_SBOM = {
    "project": {
        "name": "broken-app",
        "version": "1.0.0",
        "category": "invalid-type"  # This will fail validation
    },
    "components": [
        {
            "name": "",  # Empty name - invalid
            "version": "1.0.0",
            "type": "unknown-type",  # Invalid type
            "popularity_score": 150  # Exceeds maximum
        }
    ]
}

class BasicValidator:
    """Simple SBOM validator using standard Python libraries"""
    
    def __init__(self):
        self.name = "Basic Validator"
        self.approach = "Standard Python Libraries"
    
    def validate_sbom(self, sbom_data):
        """Validate SBOM against schema using basic approach"""
        start_time = time.time()
        result = {
            "approach": "basic",
            "valid": False,
            "errors": [],
            "warnings": [],
            "component_count": 0,
            "time_taken": 0
        }
        
        try:
            jsonschema.validate(sbom_data, SBOM_SCHEMA)
            result["valid"] = True
            result["component_count"] = len(sbom_data.get("components", []))
            
            # Check for common issues
            warnings = self.check_common_issues(sbom_data)
            result["warnings"] = warnings
            
        except jsonschema.ValidationError as e:
            result["errors"].append(f"Validation failed: {e.message}")
        except Exception as e:
            result["errors"].append(f"Error: {str(e)}")
        
        result["time_taken"] = round(time.time() - start_time, 4)
        return result
    
    def check_common_issues(self, sbom_data):
        """Check for common SBOM issues using basic logic"""
        warnings = []
        components = sbom_data.get("components", [])
        
        # Missing licenses
        no_license = [c["name"] for c in components if not c.get("license")]
        if no_license:
            warnings.append(f"Components without licenses: {', '.join(no_license[:3])}")
        
        # High risk components
        high_risk = []
        for comp in components:
            risk_score = comp.get("security", {}).get("risk_score", 0)
            if risk_score > 7:
                high_risk.append(comp["name"])
        
        if high_risk:
            warnings.append(f"High-risk components: {', '.join(high_risk)}")
        
        return warnings
    
    def analyze_components(self, sbom_data):
        """Basic component analysis using standard Python"""
        components = sbom_data.get("components", [])
        
        analysis = {
            "approach": "basic",
            "total_components": len(components),
            "component_types": {},
            "licensed_components": 0,
            "average_popularity": 0,
            "security_summary": {}
        }
        
        # Count component types using Counter
        types = [c.get("type", "unknown") for c in components]
        analysis["component_types"] = dict(Counter(types))
        
        # Count licensed components
        analysis["licensed_components"] = len([c for c in components if c.get("license")])
        
        # Calculate average popularity using basic math
        popularity_scores = [c.get("popularity_score", 0) for c in components]
        if popularity_scores:
            analysis["average_popularity"] = round(sum(popularity_scores) / len(popularity_scores), 1)
        
        # Security summary
        all_vulns = []
        risk_scores = []
        for comp in components:
            security = comp.get("security", {})
            all_vulns.extend(security.get("vulnerabilities", []))
            if security.get("risk_score"):
                risk_scores.append(security["risk_score"])
        
        analysis["security_summary"] = {
            "total_vulnerabilities": len(all_vulns),
            "average_risk_score": round(sum(risk_scores) / len(risk_scores), 1) if risk_scores else 0
        }
        
        return analysis
    
    def compare_sboms(self, sbom1, sbom2):
        """Simple SBOM comparison using set operations"""
        start_time = time.time()
        
        # Get component names from both SBOMs
        components1 = set(c["name"] for c in sbom1.get("components", []))
        components2 = set(c["name"] for c in sbom2.get("components", []))
        
        # Calculate overlap using Jaccard similarity
        common_components = components1.intersection(components2)
        all_components = components1.union(components2)
        
        if len(all_components) == 0:
            similarity = 1.0
        else:
            similarity = len(common_components) / len(all_components)
        
        return {
            "approach": "basic",
            "similarity_score": round(similarity, 3),
            "common_components": len(common_components),
            "total_unique_components": len(all_components),
            "shared_components": list(common_components),
            "processing_time": round(time.time() - start_time, 4)
        }

class DataAnalyticsValidator:
    """Enhanced SBOM validator using data analytics and machine learning approaches"""
    
    def __init__(self):
        self.name = "Data Analytics Validator"
        self.approach = "Pandas + NumPy + Machine Learning"
        self.available = DATA_ANALYTICS_MODE
    
    def validate_sbom(self, sbom_data):
        """Enhanced validation using data analytics approach"""
        if not self.available:
            return {"error": "Data analytics features require pandas, numpy, scikit-learn"}
        
        start_time = time.time()
        result = {
            "approach": "data_analytics",
            "valid": False,
            "errors": [],
            "warnings": [],
            "quality_score": 0,
            "component_count": 0,
            "time_taken": 0
        }
        
        try:
            jsonschema.validate(sbom_data, SBOM_SCHEMA)
            result["valid"] = True
            result["component_count"] = len(sbom_data.get("components", []))
            result["quality_score"] = self.calculate_data_quality_score(sbom_data)
            
            warnings = self.perform_statistical_analysis(sbom_data)
            result["warnings"] = warnings
            
        except jsonschema.ValidationError as e:
            result["errors"].append(f"Validation failed: {e.message}")
        except Exception as e:
            result["errors"].append(f"Error: {str(e)}")
        
        result["time_taken"] = round(time.time() - start_time, 4)
        return result
    
    def calculate_data_quality_score(self, sbom_data):
        """Calculate data quality score using analytics approach"""
        score = 0
        
        # Project data completeness (40 points)
        project = sbom_data.get("project", {})
        if project.get("description"):
            score += 20
        if project.get("category"):
            score += 20
        
        # Component data richness (60 points)
        components = sbom_data.get("components", [])
        if components:
            quality_points = 0
            for comp in components:
                if comp.get("license"):
                    quality_points += 15
                if comp.get("popularity_score"):
                    quality_points += 15
                if comp.get("security"):
                    quality_points += 15
            
            # Average quality across all components
            avg_quality = quality_points / len(components)
            score += min(60, avg_quality)
        
        return round(score, 1)
    
    def perform_statistical_analysis(self, sbom_data):
        """Perform statistical analysis to detect anomalies"""
        warnings = []
        components = sbom_data.get("components", [])
        
        if not components:
            return warnings
        
        # Statistical outlier detection for popularity scores
        popularity_scores = [c.get("popularity_score", 0) for c in components if c.get("popularity_score")]
        if len(popularity_scores) > 2:
            mean_pop = np.mean(popularity_scores)
            std_pop = np.std(popularity_scores)
            
            # Check for statistical outliers (2-sigma rule)
            for i, comp in enumerate(components):
                pop_score = comp.get("popularity_score", 0)
                if pop_score > 0 and abs(pop_score - mean_pop) > 2 * std_pop:
                    warnings.append(f"Statistical outlier detected for {comp['name']}: popularity {pop_score}")
        
        # Data correlation analysis - risky popular components
        for comp in components:
            popularity = comp.get("popularity_score", 0)
            risk_score = comp.get("security", {}).get("risk_score", 0)
            
            if popularity > 80 and risk_score > 6:
                warnings.append(f"High-risk popular component detected: {comp['name']}")
        
        return warnings
    
    def analyze_components(self, sbom_data):
        """Advanced component analysis using pandas DataFrame"""
        if not self.available:
            return {"error": "Data analytics features not available"}
        
        components = sbom_data.get("components", [])
        if not components:
            return {"error": "No components to analyze"}
        
        # Create pandas DataFrame for data analysis
        df_data = []
        for comp in components:
            df_data.append({
                'name': comp.get('name', ''),
                'type': comp.get('type', ''),
                'popularity': comp.get('popularity_score', 0),
                'risk_score': comp.get('security', {}).get('risk_score', 0),
                'has_license': bool(comp.get('license')),
                'vuln_count': len(comp.get('security', {}).get('vulnerabilities', []))
            })
        
        df = pd.DataFrame(df_data)
        
        # Perform DataFrame-based analytics
        analysis = {
            "approach": "data_analytics",
            "total_components": len(df),
            "type_distribution": df['type'].value_counts().to_dict(),
            "popularity_statistics": {
                "mean": round(df['popularity'].mean(), 1),
                "median": round(df['popularity'].median(), 1),
                "std_deviation": round(df['popularity'].std(), 1),
                "max": round(df['popularity'].max(), 1),
                "min": round(df['popularity'].min(), 1)
            },
            "security_analytics": {
                "avg_risk_score": round(df['risk_score'].mean(), 1),
                "risk_score_std": round(df['risk_score'].std(), 1),
                "high_risk_count": len(df[df['risk_score'] > 7]),
                "total_vulnerabilities": df['vuln_count'].sum()
            },
            "license_analytics": {
                "coverage_percentage": f"{(df['has_license'].sum() / len(df) * 100):.1f}%",
                "unlicensed_count": len(df[df['has_license'] == False])
            }
        }
        
        return analysis
    
    def compare_sboms(self, sbom1, sbom2):
        """Advanced SBOM comparison using machine learning techniques"""
        if not self.available:
            return {"error": "Data analytics features not available"}
        
        start_time = time.time()
        
        # Extract component names for ML-based text analysis
        names1 = [c["name"] for c in sbom1.get("components", [])]
        names2 = [c["name"] for c in sbom2.get("components", [])]
        
        if not names1 or not names2:
            return {"error": "No components to compare"}
        
        # TF-IDF vectorization for semantic text similarity
        all_names = names1 + names2
        try:
            vectorizer = TfidfVectorizer()
            tfidf_matrix = vectorizer.fit_transform(all_names)
            
            # Calculate cosine similarity between the two sets
            similarity_matrix = cosine_similarity(
                tfidf_matrix[:len(names1)],
                tfidf_matrix[len(names1):]
            )
            text_similarity = similarity_matrix.mean()
            
        except Exception:
            # Fallback to basic comparison if TF-IDF fails
            common = set(names1).intersection(set(names2))
            total = set(names1).union(set(names2))
            text_similarity = len(common) / len(total) if total else 0
        
        # Structural similarity analysis
        struct_sim = 1 - abs(len(names1) - len(names2)) / max(len(names1), len(names2))
        
        # Weighted similarity score (ML approach)
        overall_similarity = (text_similarity * 0.7 + struct_sim * 0.3)
        
        return {
            "approach": "data_analytics",
            "similarity_score": round(overall_similarity, 3),
            "text_similarity": round(text_similarity, 3),
            "structural_similarity": round(struct_sim, 3),
            "ml_method": "TF-IDF + Cosine Similarity",
            "components_compared": {"sbom1": len(names1), "sbom2": len(names2)},
            "processing_time": round(time.time() - start_time, 4)
        }

def run_comparison_demo():
    """Compare Basic vs Data Analytics validation approaches"""
    print("🔍 SBOM Validator: Basic vs Data Analytics Approach")
    print("=" * 60)
    
    basic_validator = BasicValidator()
    data_analytics_validator = DataAnalyticsValidator()
    
    test_cases = [
        ("Web Application", WEB_APP_SBOM),
        ("API Service", API_SERVICE_SBOM),
        ("Broken SBOM", BROKEN_SBOM)
    ]
    
    print(f"\n📋 Validation Results Comparison:")
    print("-" * 40)
    
    for name, sbom in test_cases:
        print(f"\n🔸 Testing: {name}")
        
        # Basic validation approach
        basic_result = basic_validator.validate_sbom(sbom)
        print(f"   Basic: {'✅ Valid' if basic_result['valid'] else '❌ Invalid'} "
              f"({basic_result['time_taken']}s)")
        
        if basic_result['warnings']:
            print(f"   Basic warnings: {len(basic_result['warnings'])}")
        
        # Data analytics validation approach
        if data_analytics_validator.available:
            analytics_result = data_analytics_validator.validate_sbom(sbom)
            print(f"   Data Analytics: {'✅ Valid' if analytics_result['valid'] else '❌ Invalid'} "
                  f"({analytics_result['time_taken']}s)")
            if analytics_result.get('quality_score'):
                print(f"   Quality Score: {analytics_result['quality_score']}/100")
        else:
            print(f"   Data Analytics: Not available (install pandas, numpy, scikit-learn)")
    
    # Component analysis comparison
    print(f"\n📊 Component Analysis Comparison:")
    print("-" * 40)
    
    basic_analysis = basic_validator.analyze_components(WEB_APP_SBOM)
    print(f"Basic Analysis (Web App):")
    print(f"  • Total components: {basic_analysis['total_components']}")
    print(f"  • Component types: {basic_analysis['component_types']}")
    print(f"  • Average popularity: {basic_analysis['average_popularity']}")
    print(f"  • Security: {basic_analysis['security_summary']['total_vulnerabilities']} vulnerabilities")
    
    if data_analytics_validator.available:
        analytics_analysis = data_analytics_validator.analyze_components(WEB_APP_SBOM)
        if "error" not in analytics_analysis:
            print(f"\nData Analytics Analysis (Web App):")
            print(f"  • License coverage: {analytics_analysis['license_analytics']['coverage_percentage']}")
            print(f"  • Popularity stats: {analytics_analysis['popularity_statistics']}")
            print(f"  • High-risk components: {analytics_analysis['security_analytics']['high_risk_count']}")
            print(f"  • Risk score std dev: {analytics_analysis['security_analytics']['risk_score_std']}")
    
    # Similarity comparison
    print(f"\n🔄 SBOM Similarity Comparison:")
    print("-" * 40)
    
    basic_similarity = basic_validator.compare_sboms(WEB_APP_SBOM, API_SERVICE_SBOM)
    print(f"Basic Approach: {basic_similarity['similarity_score']} "
          f"({basic_similarity['common_components']}/{basic_similarity['total_unique_components']} shared)")
    
    if data_analytics_validator.available:
        analytics_similarity = data_analytics_validator.compare_sboms(WEB_APP_SBOM, API_SERVICE_SBOM)
        if "error" not in analytics_similarity:
            print(f"Data Analytics Approach: {analytics_similarity['similarity_score']} "
                  f"(text: {analytics_similarity['text_similarity']}, "
                  f"struct: {analytics_similarity['structural_similarity']})")
            print(f"ML Method: {analytics_similarity['ml_method']}")
    
    print(f"\n💡 Approach Comparison Summary:")
    print(f"  • Basic: {basic_validator.approach}")
    print(f"    - Fast, simple, reliable")
    print(f"    - Uses standard Python libraries")
    print(f"    - Good for basic validation needs")
    print(f"  • Data Analytics: {data_analytics_validator.approach}")
    print(f"    - Statistical analysis and ML techniques")
    print(f"    - Advanced insights and anomaly detection")
    print(f"    - Better for complex data analysis")

def analyze_single_sbom(sbom_data, validator_type="basic"):
    """Analyze a single SBOM file with specified approach"""
    if validator_type == "basic":
        validator = BasicValidator()
    elif validator_type == "data_analytics" and DATA_ANALYTICS_MODE:
        validator = DataAnalyticsValidator()
    else:
        print("Data analytics mode not available, using basic validator")
        validator = BasicValidator()
    
    print(f"🔍 SBOM Analysis using {validator.name}")
    print(f"📊 Approach: {validator.approach}")
    print("-" * 50)
    
    # Validate
    result = validator.validate_sbom(sbom_data)
    print(f"Validation: {'✅ Valid' if result['valid'] else '❌ Invalid'}")
    
    if result['errors']:
        print(f"Errors:")
        for error in result['errors']:
            print(f"  • {error}")
    
    if result['warnings']:
        print(f"Warnings:")
        for warning in result['warnings']:
            print(f"  • {warning}")
    
    if result['valid']:
        # Analyze components
        analysis = validator.analyze_components(sbom_data)
        if "error" not in analysis:
            print(f"\nComponent Analysis:")
            print(f"  • Total components: {analysis['total_components']}")
            
            if 'component_types' in analysis:
                print(f"  • Types: {analysis['component_types']}")
            
            if 'average_popularity' in analysis:
                print(f"  • Average popularity: {analysis['average_popularity']}")
            elif 'popularity_statistics' in analysis:
                print(f"  • Popularity stats: {analysis['popularity_statistics']}")
            
            if 'security_summary' in analysis:
                sec = analysis['security_summary']
                print(f"  • Security: {sec['total_vulnerabilities']} vulnerabilities, "
                      f"avg risk: {sec['average_risk_score']}")
            elif 'security_analytics' in analysis:
                sec = analysis['security_analytics']
                print(f"  • Security analytics: {sec['total_vulnerabilities']} vulnerabilities, "
                      f"avg risk: {sec['avg_risk_score']} (±{sec['risk_score_std']})")
    
    return result

if __name__ == "__main__":
    print("🛡️ SBOM Validator: Basic vs Data Analytics")
    print("=" * 45)
    print(f"Mode: {'Data Analytics Available' if DATA_ANALYTICS_MODE else 'Basic Mode Only'}")
    print()
    
    # Run the comparison demo
    run_comparison_demo()
    
    print(f"\n" + "=" * 60)
    print("Demo completed! This code demonstrates:")
    print("• Basic approach: Standard Python libraries (fast, simple)")
    print("• Data Analytics approach: pandas + numpy + ML (advanced insights)")
    print("• Graceful degradation when analytics libraries aren't available")
    print("• Two distinct methodologies for the same SBOM validation task")
