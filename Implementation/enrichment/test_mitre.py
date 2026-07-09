from mitreattack.stix20 import MitreAttackData

def main():
    mitre_attack_data = MitreAttackData("Implementation/enrichment/enterprise-attack.json")
    obj = mitre_attack_data.get_object_by_attack_id("T1059", "attack-pattern")
    print(obj)
    if obj:
        tactics = mitre_attack_data.get_tactics_by_technique(obj.id)
        print(tactics)

main()
