import re


def scan_contract():
    vulnerabilities = {
        "Reentrancy Attacks": re.compile(r'.*call\(.value\('),
        "Overflow and Underflow": re.compile(r'(.*\+\+.*|.*--.*)'),
        "Uninitialized Storage Pointers": re.compile(r'storage\s+[a-zA-Z0-9_]+;'),
        "Unprotected SelfDestruct": re.compile(r'selfdestruct\('),
        "Unprotected Ether Withdrawal": re.compile(r'.transfer\('),
        "Gas Limit and Loops": re.compile(r'for\s?\(.*;.*;.*\)\s?\{'),
        "Visibility of Functions and State Variables": re.compile(
            r'(public\s+[a-zA-Z0-9_]+\s?\()|(public\s+[a-zA-Z0-9_]+;)|'
            r'(external\s+[a-zA-Z0-9_]+\s?\()|(external\s+[a-zA-Z0-9_]+;)'),
        "Unchecked Return Values": re.compile(r'call\('),
        "Short Address Attack": re.compile(r'msg\.data\.length'),
        "DelegateCall": re.compile(r'delegatecall\(')
    }

    findings = {}

    for vuln, pattern in vulnerabilities.items():
        if pattern.search(contract_code):
            findings[vuln] = "Potential vulnerability detected"
        else:
            findings[vuln] = "No obvious pattern detected"

    return findings


# Example:
contract_code = """
pragma solidity ^0.8.0;

contract VulnerableContract {
    function unsafeWithdraw(uint256 amount) public {
        msg.sender.transfer(amount);
    }
}

"""

results = scan_contract()
for vuln, result in results.items():
    print(f"{vuln}: {result}")
