package main


// if target dir exists, exit
// if target dir does not exist, copy to target.tmp, then rename to target

// copy to /srv/warp/keys/


// copy all dirs recrusively from /root/config/* to /srv/warp/config in a safe step:
// if /srv/warp/config/<dir>, stop
// if /srv/warp/config/<dir>.tmp exists, remove it
// copy to /srv/warp/config/<dir>.tmp
// mv /srv/warp/config/<dir>.tmp to /srv/warp/config/<dir>
func main() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	entries, err := os.ReadDir(path.Join(homeDir, "config"))
	if err != nil {
		panic(err)
	}

	rootPaths := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() {
			version := entry.Name()
			rootPaths[version] = path.Join(homeDir, "config", version)
		}
	}

	for version, rootPath := range rootPaths {
		targetRootPath := path.Join("/srv/warp/config", version)
		if EXISTS(targetRootPath) {
			Err.Printf("Target path already exists. Will not copy. (%s)", targetRootPath)
			continue
		}
		targetTempRootPath := path.Join("/srv/warp/config", fmt.Sprintf("%s.tmp", version))
		if EXISTS(targetTempRootPath) {
			RM(targetTempRootPath)
		}
		err := copy(rootPath, targetTempRootPath)
		if err != nil {
			Err.Printf("Error during copy. Version %s will not be deployed. %s", version, err)
			continue
		}
		err = move(targetTempRootPath, targetRootPath)
		if err != nil {
			Err.Printf("Error during move. Version %s will not be deployed. %s", version, err)
		}
	}
}

func copy(sourceRootPath string, targetRootPath string) error {
	// FIXME
}

func move(sourceRootPath string, targetRootPath string) error {
	// FIXME
}


