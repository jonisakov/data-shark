from report_engine import ReportEngine

def main():
    report = ReportEngine()
    
    report._add_report_row('123','123','detected')
    report._add_report_row('123','123','not_detected')

    report._generate_report("C:\\temp\\report1.html")

if __name__ == "__main__":
    main()