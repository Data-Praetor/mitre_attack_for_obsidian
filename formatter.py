import json,os

with open('enterprise-attack.json') as json_file:
	data_store = json.load(json_file)

# All data in "objects" key
	
def formatting(entry):
	write_data = "---\ntags:\n"
	write_data += f"- ID/{entry["external_references"][0]["external_id"].replace(".","/")}\n"
	
	# MITRE Domains
	for domain in entry["x_mitre_domains"]:
		write_data += f"- Domain/{domain}\n"

	# "Tactics" in website's infobox
	for tactic in entry["kill_chain_phases"]:
		write_data += f'- Tactics/{tactic["phase_name"]}\n'

	for platform in entry["x_mitre_platforms"]:
		platform = platform.replace(" ", "-")
		write_data += f'- Platform/{platform}\n'
	
	## Non-tag properties
	
	# Remote support
	if "x_mitre_remote_support" in entry:
		write_data += f'Remote Support: {entry["x_mitre_remote_support"]}\n'

	if "x_mitre_permissions_required" in entry:
		write_data += "Permissions Required:\n"
		for perm in entry["x_mitre_permissions_required"]:
			write_data += f'    - {perm}\n'
	
	if "x_mitre_system_requirements" in entry:
		write_data += f'Prerequisites: {entry["x_mitre_system_requirements"][0]}\n'

	# Data Sources
	# Some PRE techniques have missing data source field >.>
	if "x_mitre_data_sources" in entry:
		write_data += f"Data Sources:\n"
		data_dict = {}
		for item in entry["x_mitre_data_sources"]:
			category, item_name = item.split(": ")
			data_dict.setdefault(category, []).append(item_name)
		sorted_categories = sorted(data_dict.keys())
		for category in sorted_categories:
			write_data += f"    - {category}\n"
			for item in sorted(data_dict[category]):
				write_data += f"        - {item}\n"

	write_data += "---\n"
	write_data += f'# {entry["name"]}\n'

	# Replace citations
	ref_num = 1
	for item in entry["external_references"][1:]:
		pattern = f"(Citation: {item["source_name"]})"
		# One book reference
		if "url" in item:
			entry["description"] = entry["description"].replace(pattern, f'<sup><a href="{item['url']}">[{ref_num}]</a></sup>')
			ref_num += 1

	write_data += f'{entry["description"]}\n\n---\n\n'
	
	
	## Full scan for references
	
	# Detections
	write_data += "# Detection\n\n"
	for scan in data_store["objects"][1:]:
		if ("target_ref" in scan):
			if (scan["target_ref"] == entry["id"]):
				if ("x_mitre_deprecated" in scan):
					if not (scan["x_mitre_deprecated"]):
						if (scan["relationship_type"] == "detects"):
							if "external_references" in scan:
								for item in scan["external_references"]:
									pattern = f"(Citation: {item["source_name"]})"
									# One book reference
									if "url" in item:
										scan["description"] = scan["description"].replace(pattern, f'<sup><a href="{item["url"]}">[{ref_num}]</a></sup>')
										ref_num += 1
								write_data += f"{scan["description"]}\n\n"

	write_data += "---\n"
	

	# Mitigations
	write_data += "\n# Mitigation\n\n"
	
	for scan in data_store["objects"][1:]:
		if ("target_ref" in scan):
			if (scan["target_ref"] == entry["id"]):
				if ("x_mitre_deprecated" in scan):
					if not (scan["x_mitre_deprecated"]):
						if (scan["relationship_type"] == "mitigates"):
							if "external_references" in scan:
								for item in scan["external_references"]:
									pattern = f"(Citation: {item["source_name"]})"
									# One book reference
									if "url" in item:
										scan["description"] = scan["description"].replace(pattern, f'<sup><a href="{item["url"]}">[{ref_num}]</a></sup>')
										ref_num += 1
								write_data += f"{scan["description"]}\n\n"

	return write_data

## Main

# For Technique ID and Name dictionary
id_dict = []

for entry in data_store["objects"][1:]:
	if (entry["type"] == "attack-pattern"):
		if not (("revoked" in entry) and entry["revoked"]) and not (("x_mitre_deprecated" in entry) and entry["x_mitre_deprecated"]):
			technique = entry["external_references"][0]["external_id"].split(".")[0]
			safe_name = entry["name"].replace("/", " or ")

			tactics = entry["kill_chain_phases"][0]["phase_name"].replace("-", " ").title()
			hierarchy = f"{tactics}/{technique}"
			
			# Technique Main entries
			if not entry["x_mitre_is_subtechnique"]:
				# Gather unique top-level techniques from here again
				rename_technique_id = entry["external_references"][0]["external_id"].split(".")[0]
				rename_safe_name = entry["name"].replace("/", " or ")
				reference_list = [{'parent_dir': tactics, 'old_val': rename_technique_id, 'new_val': rename_safe_name}]
				id_dict.append(reference_list)

				file_path = f'{hierarchy}/{safe_name}.md'
				os.makedirs(os.path.dirname(file_path), exist_ok=True)
				with open(f"{file_path}.md", "wb") as file:
					file.write(formatting(entry).encode("utf-8", errors="replace"))
			
			# Sub Technique entries
			if entry["x_mitre_is_subtechnique"]:
				file_path = f'{hierarchy}/{safe_name}.md'
				os.makedirs(os.path.dirname(file_path), exist_ok=True)
				with open(f"{file_path}.md", "wb") as file:
					file.write(formatting(entry).encode("utf-8", errors="replace"))

# Replace IDs with Technique names
for e in id_dict:
	pdir = e[0]["parent_dir"]
	odir = e[0]["old_val"]
	ndir = e[0]["new_val"]
	old_path = os.path.join(pdir, odir)
	new_path = os.path.join(pdir, ndir)
	if os.path.exists(old_path) and not os.path.exists(new_path):
		os.rename(old_path, new_path)
