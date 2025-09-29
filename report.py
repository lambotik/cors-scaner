from colorama import Fore, Style


def print_report(headers, issues):
    print(Fore.CYAN + "\n🔐 Заголовки безопасности:" + Style.RESET_ALL)
    for k, v in headers.items():
        status = v if v else "❌ Отсутствует"
        print(f"{k}: {status}")

    print(Fore.YELLOW + "\n⚠️ Выявленные проблемы:" + Style.RESET_ALL)
    for issue in issues:
        print(issue)
