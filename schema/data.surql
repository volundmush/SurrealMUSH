-- Helper functions.
DEFINE FUNCTION OVERWRITE fn::admin_override($user: record<user>, $min: int) {
    RETURN $user.admin_level >= $min AND $user.admin_mantle;
};

DEFINE PARAM OVERWRITE $baseConfig VALUE {
    "name_length": [1, 32]
};

DEFINE FUNCTION OVERWRITE fn::check_length($value: string, $lengths: array<int>, $title: string) -> bool {
    IF $value.len() < $lengths[0] {
        THROW $title + " is too short! (min " + $lengths[0] + ")";
    } ELSE IF $value.len() > $lengths[1] {
        THROW $title + " is too long! (max " + $lengths[1] + ")";
    };
    RETURN true;
};

DEFINE FUNCTION OVERWRITE fn::check_name_base($value: string, $lengths: array<int>, $title: string) -> bool {
    fn::check_length($value, $lengths, $title);
    IF !$value.is_ascii() {
        THROW $title + " must be ASCII! No special characters!";
    };
    IF $value.matches("[\\t\\r\\n]") {
        THROW $title + " cannot contain tabs or newlines!";
    };
    IF $value.matches("\\s+") {
        THROW $title + " cannot contain consecutive spaces!";
    };
    RETURN true;
};

DEFINE FUNCTION OVERWRITE fn::check_name($value: string, $lengths: array<int>, $title: string) -> bool {
    fn::check_name_base($value, $lengths, $title);
    IF !$value.matches("^[ A-Za-z0-9!\\?,\\.\\-\\']+$") {
        THROW $title + " can only contain alphanumberic characters, single spaces, and: . ? ! - , ' `";
    };
    RETURN true;
};

DEFINE PARAM OVERWRITE $userConfig VALUE {
    "base_character_slots": 8
};

-- Auth: User Table
DEFINE TABLE OVERWRITE user SCHEMAFULL
    PERMISSIONS
        FOR select
            WHERE $auth.id = id OR fn::admin_override($auth.id, 5)
        FOR create
            WHERE fn::admin_override($auth.id, 5)
        FOR update
            WHERE fn::admin_override($auth.id, 5) AND $auth.admin_level > $this.admin_level
        FOR delete
            WHERE fn::admin_override($auth.id, 7) AND $auth.admin_level > $this.admin_level
;

DEFINE FIELD OVERWRITE name ON user TYPE string VALUE $value.trim() ASSERT fn::check_name($value, $baseConfig.name_length, "User Name");
DEFINE FIELD OVERWRITE name_lower ON user TYPE string VALUE $value.trim().lowercase();
DEFINE FIELD OVERWRITE created_at ON user TYPE datetime READONLY DEFAULT ALWAYS time::now();
DEFINE FIELD OVERWRITE updated_at ON user TYPE datetime READONLY VALUE time::now();
DEFINE FIELD OVERWRITE deleted_name ON user TYPE option<string> DEFAULT none;
DEFINE FIELD OVERWRITE deleted_at ON user TYPE option<datetime> DEFAULT none;
DEFINE FIELD OVERWRITE is_deleted ON user COMPUTED !!deleted_at;
DEFINE FIELD OVERWRITE admin_mantle ON user TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE extra_character_slots ON user TYPE int DEFAULT 0;

DEFINE INDEX OVERWRITE name_lower_unique ON user FIELDS name_lower UNIQUE CONCURRENTLY;

-- Auth: Email Table
DEFINE TABLE OVERWRITE linked_email SCHEMAFULL;
DEFINE FIELD OVERWRITE user ON linked_email TYPE record<user> READONLY;
DEFINE FIELD OVERWRITE email ON linked_email TYPE string READONLY ASSERT $value.is_email();
DEFINE FIELD OVERWRITE provider ON linked_email TYPE string READONLY;
DEFINE FIELD OVERWRITE created_at ON linked_email TYPE datetime READONLY DEFAULT ALWAYS time::now();
DEFINE FIELD OVERWRITE verified_at ON linked_email TYPE option<datetime> DEFAULT none;
DEFINE FIELD OVERWRITE metadata ON linked_email TYPE object FLEXIBLE;

DEFINE INDEX OVERWRITE email_unique ON linked_email FIELDS email UNIQUE CONCURRENTLY;

-- Auth: Passwords Table
DEFINE TABLE OVERWRITE password SCHEMAFULL
    PERMISSIONS
        FOR select
            WHERE $auth.id = $this.user OR fn::admin_override($auth.id, 7)
        FOR create,delete,update
            WHERE fn::admin_override($auth.id, 7)
;
DEFINE FIELD OVERWRITE user ON password TYPE record<user> READONLY;
DEFINE FIELD OVERWRITE created_at ON password TYPE datetime READONLY DEFAULT ALWAYS time::now();
DEFINE FIELD OVERWRITE hash ON password TYPE string READONLY;

DEFINE FIELD OVERWRITE passwords ON user TYPE array<record<password>> COMPUTED (<~password ?? []);

DEFINE FUNCTION OVERWRITE fn::latest_password($user: record<user>) -> option<record<password>> {
    LET $latest_id = SELECT id FROM ONLY password WHERE user = $user ORDER BY created_at DESC LIMIT 1;
    RETURN $latest_id;
};

DEFINE FUNCTION OVERWRITE fn::rename_thing($target: record, $new_name: string) {
    $target.name = $new_name;
    $target.name_lower = $new_name.lowercase();
};



DEFINE FUNCTION OVERWRITE fn::set_user_password($user: record<user>, $password: string) {
    IF $user.deleted_at {
        throw "User already deleted.";
    };
    IF $auth.id.admin_level <= $user.admin_level {
        throw "Insufficient permissions.";
    };
    CREATE password SET user = $user, hash = crypto::argon2::generate($password);
} PERMISSIONS WHERE fn::admin_override($auth.id, 5)
;

DEFINE FUNCTION OVERWRITE fn::create_user($name: string, $password: string) {
    LET $user =CREATE user SET name = $name.trim();
    fn::set_user_password($user, $password);
    RETURN $user;
} PERMISSIONS WHERE fn::admin_override($auth.id, 5)
;

DEFINE FUNCTION OVERWRITE fn::rename_user($user: record<user>, $new_name: string) {
    IF $user.deleted_at {
        THROW "User already deleted.";
    };
    IF $auth.id.admin_level <= $user.admin_level {
        THROW "Insufficient permissions.";
    };
    fn::rename_thing($user, $new_name);
} PERMISSIONS WHERE fn::admin_override($auth.id, 5)
;

DEFINE FUNCTION OVERWRITE fn::delete_user($user: record<user>) {
    IF $user.deleted_at {
        THROW "User already deleted.";
    };
    IF $auth.id.admin_level <= $user.admin_level {
        THROW "Insufficient permissions.";
    };
    UPDATE $user SET deleted_name = $user.name, deleted_at = time::now();
} PERMISSIONS WHERE fn::admin_override($auth.id, 5)
;

DEFINE FUNCTION OVERWRITE fn::undelete_user($user: record<user>) {
    IF !$user.deleted_at {
        THROW "User not deleted.";
    };
    IF $auth.id.admin_level <= $user.admin_level {
        THROW "Insufficient permissions.";
    };
    UPDATE $user SET name = deleted_name;
    UPDATE $user SET deleted_name = null, deleted_at = null;
} PERMISSIONS WHERE fn::admin_override($auth.id, 5)
;

-- Login Records
DEFINE TABLE OVERWRITE login_tracker SCHEMAFULL
    PERMISSIONS
        FOR select
            WHERE $auth.id == user OR fn::admin_override($auth.id, 5)
;
DEFINE FIELD OVERWRITE user ON login_tracker TYPE record<user> READONLY REFERENCE;
DEFINE FIELD OVERWRITE ip_address ON login_tracker TYPE string READONLY ASSERT $value.is_ip();
DEFINE FIELD OVERWRITE created_at ON login_tracker TYPE datetime READONLY DEFAULT ALWAYS time::now();
DEFINE FIELD OVERWRITE success ON login_tracker TYPE bool READONLY DEFAULT false;

DEFINE FUNCTION OVERWRITE fn::check_password_rhost($password: record<password>, $entry: string) -> bool {
    -- This isn't going to work without Surrealism.
    -- Rhost uses: https://man7.org/linux/man-pages/man3/crypt.3.html
    LET $pieces = $password.hash.split("$");
    LET $version = $pieces[0];
    LET $salt = $pieces[1];
    LET $hash = $pieces[2];
    IF $version == "6" {
        RETURN crypto::sha512($entry) == $hash;
    };
    RETURN false;
};

DEFINE FUNCTION OVERWRITE fn::check_password($password: record<password>, $entry: string) -> bool {
    IF $password.hash.starts_with("$argon2") {
        RETURN crypto::argon2::compare($password.hash, $entry);
    } ELSE IF $password.hash.starts_with("$6") {
        LET $result = fn::check_password_rhost($password, $entry);
        IF $result {
            CREATE password SET user = $user, hash = crypto::argon2::generate($entry);
        }
        RETURN $result;
    };
    RETURN false;
};

DEFINE FUNCTION OVERWRITE fn::login_user($username: string, $password: string) {
    LET $user_search = SELECT * FROM ONLY user WHERE name_lower = $username.trim().lowercase() LIMIT 1;
    IF !$user_search {
        throw "Invalid credentials.";
    };

    LET $user = $user_search.id;

    LET $latest_password = fn::latest_password($user);
    IF !$latest_password {
        throw "Invalid credentials.";
    };

    LET $ip = session::ip() ?? "";

    IF !crypto::argon2::compare($user.password, $password) {
        IF $ip.is_ip() {
            CREATE login_tracker SET user = $user, ip_address = $ip, success = false;
        };
        throw "Invalid credentials.";
    };

    IF $ip.is_ip() {
        CREATE login_tracker SET user = $user, ip_address = $ip, success = true;
    };

    RETURN $user;
};

-- Login rules.
DEFINE ACCESS OVERWRITE account ON DATABASE TYPE RECORD
    SIGNUP (fn::create_user($username, $password))
    SIGNIN (fn::login_user($username, $password))
    WITH REFRESH
    DURATION FOR TOKEN 15m, FOR SESSION 12h;


DEFINE FUNCTION OVERWRITE fn::available_slots($user: record<user>) -> bool {
    IF $user.character_slots_available > 0 {
        RETURN true;
    };
    THROW "No available slots.";
};

-- The PC (player character) table.
DEFINE TABLE OVERWRITE pc SCHEMAFULL
    PERMISSIONS
        FOR create
            WHERE fn::admin_override($auth.id, 5) OR fn::available_slots($user)
        FOR select
            WHERE !$this.is_deleted OR fn::admin_override($auth.id, 5)
        FOR update
            WHERE fn::admin_override($auth.id, 5) OR $auth.id == $this.user
;
DEFINE FIELD OVERWRITE user ON pc TYPE record<user> REFERENCE
    PERMISSIONS
        FOR select
            WHERE $auth.id == $this.user OR fn::admin_override($auth.id, 5)
        FOR update
            WHERE fn::admin_override($auth.id, 5)
;
DEFINE FIELD OVERWRITE name ON pc TYPE string VALUE $value.trim() ASSERT fn::check_length($value, $baseConfig.name_length, "Name")
    VALUE $value.trim()
    ASSERT $value.len() >= 1
    PERMISSIONS
        FOR select
            WHERE true
        FOR update
            WHERE ($auth.id == $this.user AND !$this.is_approved) OR fn::admin_override($auth.id, 5)
;
DEFINE FIELD OVERWRITE name_lower ON pc TYPE string VALUE $value.trim().lowercase() ASSERT fn::check_length($value, $baseConfig.name_length, "Name");
DEFINE FIELD OVERWRITE created_at ON pc TYPE datetime READONLY DEFAULT ALWAYS time::now();
DEFINE FIELD OVERWRITE updated_at ON pc TYPE datetime READONLY VALUE time::now();
DEFINE FIELD OVERWRITE deleted_at ON pc TYPE option<datetime> DEFAULT none
    PERMISSIONS
        FOR select
            WHERE true
        FOR update
            WHERE fn::admin_override($auth.id, 5)
;
DEFINE FIELD OVERWRITE is_deleted ON pc COMPUTED !!deleted_at;
DEFINE FIELD OVERWRITE approved_at ON pc TYPE option<datetime> DEFAULT none
PERMISSIONS
    FOR select
        WHERE true
    FOR update
        WHERE fn::admin_override($auth.id, 5)
;
DEFINE FIELD OVERWRITE is_approved ON pc COMPUTED !!approved_at;
DEFINE FIELD OVERWRITE is_playable ON pc COMPUTED is_approved AND !is_deleted;

DEFINE INDEX OVERWRITE name_lower_unique ON pc FIELDS name_lower UNIQUE CONCURRENTLY;

DEFINE FUNCTION OVERWRITE fn::active_pcs($in: array<record<user>> | NONE) -> array<record<pc>> {
    RETURN ($in ?? [])[WHERE !$this.is_deleted AND $this.is_approved];
};

-- Adding some reverse lookups.
DEFINE FIELD OVERWRITE pcs ON user TYPE array<record<pc>> COMPUTED (<~pc ?? []);
DEFINE FIELD OVERWRITE pcs_active ON user TYPE array<record<pc>> COMPUTED fn::active_pcs(<~pc);
DEFINE FIELD OVERWRITE character_slots ON user TYPE int COMPUTED $userConfig.base_character_slots + $this.extra_character_slots;
DEFINE FIELD OVERWRITE character_slots_available ON user TYPE int COMPUTED $this.character_slots - fn::active_pcs(<~pc).len();

-- The Location system for roleplaying.
DEFINE TABLE OVERWRITE location SCHEMAFULL;

-- Faction System: Faction Table
DEFINE TABLE OVERWRITE faction SCHEMAFULL;
DEFINE FIELD OVERWRITE category ON faction TYPE string DEFAULT "Uncategorized";
DEFINE FIELD OVERWRITE name ON faction TYPE string VALUE $value.trim() ASSERT fn::check_length($value, $baseConfig.name_length, "Faction Name");
DEFINE FIELD OVERWRITE name_lower ON faction TYPE string VALUE $value.trim().lowercase() ASSERT fn::check_length($value, $baseConfig.name_length, "Faction Name");
DEFINE FIELD OVERWRITE abbreviation ON faction TYPE string;
DEFINE FIELD OVERWRITE permissions ON faction TYPE set<string>;
DEFINE FIELD OVERWRITE hidden ON faction TYPE bool DEFAULT true;
DEFINE FIELD OVERWRITE private ON faction TYPE bool DEFAULT true;
DEFINE FIELD OVERWRITE open ON faction TYPE bool DEFAULT false;
DEFINE FIELD OVERWRITE kick_rank ON faction TYPE int DEFAULT 2;
DEFINE FIELD OVERWRITE can_leave ON faction TYPE bool DEFAULT true;
DEFINE FIELD OVERWRITE start_rank ON faction TYPE int DEFAULT 4;

DEFINE INDEX OVERWRITE name_lower_unique ON faction FIELDS name_lower UNIQUE CONCURRENTLY;


-- Faction System: Rank Table
DEFINE TABLE OVERWRITE faction_rank SCHEMAFULL;
DEFINE FIELD OVERWRITE faction ON faction_rank TYPE record<faction> REFERENCE;
DEFINE FIELD OVERWRITE value ON faction_rank TYPE int;
DEFINE FIELD OVERWRITE name ON faction_rank TYPE string VALUE $value.trim() ASSERT fn::check_length($value, $baseConfig.name_length, "Faction Rank Name");
DEFINE FIELD OVERWRITE name_lower ON faction_rank TYPE string VALUE $value.trim().lowercase() ASSERT fn::check_length($value, $baseConfig.name_length, "Faction Rank Name");
DEFINE FIELD OVERWRITE permissions ON faction_rank TYPE set<string>;

DEFINE INDEX OVERWRITE faction_rank_values_unique ON faction_rank FIELDS faction, value UNIQUE;
DEFINE INDEX OVERWRITE faction_rank_name_lower_unique ON faction_rank FIELDS name_lower UNIQUE CONCURRENTLY;

-- Faction System:: Memberships
DEFINE TABLE OVERWRITE faction_membership SCHEMAFULL;
DEFINE FIELD OVERWRITE faction ON faction_membership TYPE record<faction> REFERENCE;
DEFINE FIELD OVERWRITE member ON faction_membership TYPE record<pc> REFERENCE;
DEFINE FIELD OVERWRITE rank ON faction_membership TYPE record<faction_rank> REFERENCE;
DEFINE FIELD OVERWRITE permissions ON faction_membership TYPE set<string>;
DEFINE FIELD OVERWRITE title ON faction_membership TYPE option<string>;
DEFINE FIELD OVERWRITE all_permissions ON faction_membership COMPUTED permissions + rank.permissions + faction.permissions;

DEFINE INDEX OVERWRITE faction_membership_unique ON faction_membership FIELDS faction, member UNIQUE;

DEFINE FIELD OVERWRITE holders ON faction_rank COMPUTED (<~faction_membership ?? []);
DEFINE FIELD OVERWRITE faction_memberships ON pc COMPUTED (<~faction_membership ?? []);
DEFINE FIELD OVERWRITE members ON faction COMPUTED <set>(<~faction_membership ?? []).map(|$m| $m.member);

-- The Theme System for roleplaying.
DEFINE TABLE OVERWRITE theme SCHEMAFULL;
DEFINE FIELD OVERWRITE created_at ON theme TYPE datetime READONLY DEFAULT ALWAYS time::now();
DEFINE FIELD OVERWRITE updated_at ON theme TYPE datetime READONLY VALUE time::now();
DEFINE FIELD OVERWRITE deleted_at ON theme TYPE option<datetime> DEFAULT none;
DEFINE FIELD OVERWRITE is_deleted ON theme COMPUTED !!deleted_at;
DEFINE FIELD OVERWRITE approved_at ON theme TYPE option<datetime> DEFAULT none;
DEFINE FIELD OVERWRITE is_approved ON theme COMPUTED !!approved_at;

DEFINE FIELD OVERWRITE category ON theme TYPE string DEFAULT 'Uncategorized';
DEFINE FIELD OVERWRITE name ON theme TYPE string;
DEFINE FIELD OVERWRITE name_lower ON theme TYPE string READONLY VALUE $name.lowercase();

DEFINE INDEX OVERWRITE theme_name_unique ON theme FIELDS name_lower UNIQUE CONCURRENTLY;

-- Theme System: Members
DEFINE TABLE OVERWRITE theme_member SCHEMAFULL;
DEFINE FIELD OVERWRITE theme ON theme_member TYPE record<theme> REFERENCE;
DEFINE FIELD OVERWRITE member ON theme_member TYPE record<user> REFERENCE;
DEFINE FIELD OVERWRITE role ON theme_member TYPE int DEFAULT 0;

DEFINE INDEX OVERWRITE theme_member_theme_member ON theme_member FIELDS theme, member UNIQUE CONCURRENTLY;

DEFINE FIELD OVERWRITE members ON theme COMPUTED (<~theme_member ?? []).map(|$m| $m.member);

-- Permission Checking System
DEFINE FUNCTION OVERWRITE fn::lock_check_rule_faction($pc: record<pc>, $faction: record<faction>, $rule: array) -> bool {
    IF $rule.len() < 2 {
        RETURN false;
    };

    LET $mem = SELECT * FROM faction_membership WHERE faction = $rec AND member = $pc;
    IF !$mem {
        RETURN false;
    };

    IF $rule[0] == "permission" {
        RETURN $mem.all_permissions.contains($rule[1]);
    } ELSE IF $rule[0] == "rank" {
        RETURN $mem.rank.value >= $rule[1];
    };
    RETURN false;
}
COMMENT "Helper function for handling extended Faction Locks."
;

DEFINE FUNCTION OVERWRITE fn::lock_check_rule($pc: record<pc>, $rule : array|bool|record, $resource: record) -> bool {
    IF type::is_bool($rule) {
        -- a simple bool check. If this is True, access is granted. if false, then only admin can access it.
        RETURN $rule;
    }
    ELSE IF type::is_record($rule) {
        -- Basic membership checks.
        LET $rtype = meta::tb($rule);
        IF $rtype == "user" {
            RETURN $pc.user.id == $rule.id;
        } ELSE IF $rtype == "faction" OR $rtype == "theme" {
            RETURN $rule.members.contains($pc);
        }

    }
    ELSE IF type::is_array($rule) {
        -- This is a complex rule, like [$faction, "permission", "whichperm"]
        IF $rule.is_empty() {
            RETURN false;
        };
        LET $rec = $rule[0];
        IF !type::is_record($rec) {
            RETURN false;
        };

        LET $rtype = meta::tb($rec);
        IF $rtype == "faction" {
            RETURN fn::lock_check_rule_faction($pc, $rec, $rule.slice(1..));
        };

    };

    RETURN false;
}
COMMENT "Helper function used by fn::lock_check. Don't call directly."
;

DEFINE FUNCTION OVERWRITE fn::lock_check($pc: record<user>, $rules: array) -> bool {
    IF !$rules {
        RETURN false;
    };

    FOR $rule IN $rules {
        IF fn::lock_check_rule($pc, $rule) {
            RETURN true;
        };
    };

    RETURN false;
}
COMMENT "Core function for lock checks."
;

-- Roleplay Logging: Actors
DEFINE TABLE OVERWRITE actor SCHEMAFULL;
DEFINE FIELD OVERWRITE pc ON actor TYPE record<pc> REFERENCE;
DEFINE FIELD OVERWRITE name ON actor TYPE string;
DEFINE FIELD OVERWRITE name_lower ON actor TYPE string READONLY VALUE $name.lowercase();

DEFINE INDEX OVERWRITE actor_unique ON actor FIELDS pc, name_lower UNIQUE;

-- Roleplay Logging: ActingAs
DEFINE TABLE OVERWRITE acting_as SCHEMAFULL;
DEFINE FIELD OVERWRITE user ON acting_as TYPE record<user> REFERENCE;
DEFINE FIELD OVERWRITE actor ON acting_as TYPE record<actor> REFERENCE;

DEFINE INDEX OVERWRITE acting_as_unique ON acting_as FIELDS user, actor UNIQUE;

-- Roleplay Logging: Plots
DEFINE TABLE OVERWRITE plot SCHEMAFULL;
DEFINE FIELD OVERWRITE title ON plot TYPE string;
DEFINE FIELD OVERWRITE title_lower ON plot TYPE string READONLY VALUE $title.lowercase();
DEFINE FIELD OVERWRITE description ON plot TYPE option<string>;
DEFINE FIELD OVERWRITE outcome ON plot TYPE option<string>;
DEFINE FIELD OVERWRITE start_date ON plot TYPE option<datetime>;
DEFINE FIELD OVERWRITE end_date ON plot TYPE option<datetime>;
DEFINE FIELD OVERWRITE created_at ON plot TYPE datetime READONLY DEFAULT ALWAYS time::now();
DEFINE FIELD OVERWRITE updated_at ON plot TYPE datetime READONLY VALUE time::now();
DEFINE FIELD OVERWRITE deleted_at ON plot TYPE option<datetime> DEFAULT none;
DEFINE FIELD OVERWRITE is_deleted ON plot COMPUTED !!deleted_at;

DEFINE TABLE OVERWRITE plot_runner SCHEMAFULL;
DEFINE FIELD OVERWRITE plot ON plot_runner TYPE record<plot> REFERENCE;
DEFINE FIELD OVERWRITE runner ON plot_runner TYPE record<pc> REFERENCE;
DEFINE FIELD OVERWRITE role ON plot_runner TYPE int DEFAULT 0;

DEFINE INDEX OVERWRITE plot_runner_unique ON plot_runner FIELDS plot,runner UNIQUE CONCURRENTLY;

-- Roleplay Logging: Scenes
DEFINE TABLE OVERWRITE scene SCHEMAFULL;
DEFINE FIELD OVERWRITE title ON scene TYPE string;
DEFINE FIELD OVERWRITE title_lower ON scene TYPE string READONLY VALUE $value.lowercase();
DEFINE FIELD OVERWRITE pitch ON scene TYPE option<string>;
DEFINE FIELD OVERWRITE created_at ON scene TYPE datetime READONLY DEFAULT ALWAYS time::now();
DEFINE FIELD OVERWRITE updated_at ON scene TYPE datetime READONLY VALUE time::now();
DEFINE FIELD OVERWRITE started_at ON scene TYPE option<datetime> DEFAULT none;
DEFINE FIELD OVERWRITE activity_at ON scene TYPE option<datetime> DEFAULT none;
DEFINE FIELD OVERWRITE finished_at ON scene TYPE option<datetime> DEFAULT none;
DEFINE FIELD OVERWRITE deleted_at ON scene TYPE option<datetime> DEFAULT none;
DEFINE FIELD OVERWRITE is_deleted ON scene COMPUTED !!deleted_at;
DEFINE FIELD OVERWRITE status ON scene TYPE int DEFAULT 0;
DEFINE FIELD OVERWRITE capacity ON scene TYPE int DEFAULT 0;

DEFINE INDEX OVERWRITE scene_unique ON scene FIELDS title_lower UNIQUE CONCURRENTLY;

DEFINE TABLE OVERWRITE scene_plot TYPE RELATION IN plot OUT scene SCHEMAFULL;

-- Channel System: functions
DEFINE FUNCTION OVERWRITE fn::channel_lock_helper($pc: record<pc>, $channel: record<channel>, $check: string) -> bool {
    -- The channels 'inherit' their system's locks if they don't have their own.
    LET $rules = $channel.locks[$check];
    IF !$rules {
        LET $rules = $channel.sys.locks[$check];
    };
    RETURN fn::lock_check($pc, $rules);
};

DEFINE FUNCTION OVERWRITE fn::channel_lock_check($pc: record<pc>, $channel: record<channel>, $check: string) -> bool {
    LET $results = fn::channel_lock_helper($pc, $channel, $check);
    IF !$results {
        IF $check == "talk" {
            RETURN fn::channel_lock_check($pc, $channel, "moderate");
        } ELSE IF $check == "moderate" {
            RETURN fn::channel_lock_check($pc, $channel, "admin");
        };
    };
    RETURN true;
};

-- Channel System: ChanSys
DEFINE TABLE OVERWRITE channel_sys SCHEMAFULL
    PERMISSIONS
        FOR select, update, create
            WHERE fn::admin_override($auth, 6)
        FOR delete
            WHERE fn::admin_override($auth, 7)
;
DEFINE FIELD OVERWRITE name ON channel_sys TYPE string;
DEFINE FIELD OVERWRITE name_lower ON channel_sys TYPE string READONLY VALUE $name.lowercase();
DEFINE FIELD OVERWRITE created_at ON channel_sys TYPE datetime READONLY DEFAULT ALWAYS time::now();
DEFINE FIELD OVERWRITE updated_at ON channel_sys TYPE datetime READONLY VALUE time::now();
DEFINE FIELD OVERWRITE deleted_at ON channel_sys TYPE option<datetime> DEFAULT none;
DEFINE FIELD OVERWRITE is_deleted ON channel_sys COMPUTED !!deleted_at;
DEFINE FIELD OVERWRITE locks ON channel_sys TYPE object FLEXIBLE;

DEFINE INDEX OVERWRITE channel_sys_name_unique ON channel_sys FIELDS name_lower UNIQUE CONCURRENTLY;

-- Channel System: Channel
DEFINE TABLE OVERWRITE channel SCHEMAFULL
    PERMISSIONS
        FOR select, update, create
            WHERE fn::admin_override($auth, 6)
        FOR delete
            WHERE fn::admin_override($auth, 7)
;
DEFINE FIELD OVERWRITE sys ON channel TYPE record<channel_sys> REFERENCE;
DEFINE FIELD OVERWRITE name ON channel TYPE string;
DEFINE FIELD OVERWRITE name_lower ON channel TYPE string READONLY VALUE $name.lowercase();
DEFINE FIELD OVERWRITE created_at ON channel TYPE datetime READONLY DEFAULT ALWAYS time::now();
DEFINE FIELD OVERWRITE updated_at ON channel TYPE datetime READONLY VALUE time::now();
DEFINE FIELD OVERWRITE deleted_at ON channel TYPE option<datetime> DEFAULT none;
DEFINE FIELD OVERWRITE is_deleted ON channel COMPUTED !!deleted_at;
DEFINE FIELD OVERWRITE locks ON channel TYPE object FLEXIBLE;

DEFINE INDEX OVERWRITE channel_name_unique ON channel FIELDS sys,name_lower UNIQUE CONCURRENTLY;

-- Channel System: Message
DEFINE TABLE OVERWRITE channel_msg SCHEMAFULL;
DEFINE FIELD OVERWRITE channel ON channel_msg TYPE record<channel> REFERENCE;
DEFINE FIELD OVERWRITE acting_as ON channel_msg TYPE record<acting_as> REFERENCE;
DEFINE FIELD OVERWRITE content ON channel_msg TYPE string;
DEFINE FIELD OVERWRITE created_at ON channel_msg TYPE datetime READONLY DEFAULT ALWAYS time::now();
DEFINE FIELD OVERWRITE updated_at ON channel_msg TYPE datetime READONLY VALUE time::now();
DEFINE FIELD OVERWRITE deleted_at ON channel_msg TYPE option<datetime> DEFAULT none;
DEFINE FIELD OVERWRITE is_deleted ON channel_msg COMPUTED !!deleted_at;

DEFINE INDEX OVERWRITE channel_msg_channel ON channel_msg FIELDS channel,created_at UNIQUE CONCURRENTLY;

-- BBS System: Boards
DEFINE TABLE OVERWRITE bbs_board SCHEMAFULL;
DEFINE FIELD OVERWRITE name ON bbs_board TYPE string;
DEFINE FIELD OVERWRITE description ON bbs_board TYPE string;
DEFINE FIELD OVERWRITE created_at ON bbs_board TYPE datetime READONLY DEFAULT ALWAYS time::now();
DEFINE FIELD OVERWRITE updated_at ON bbs_board TYPE datetime READONLY VALUE time::now();
DEFINE FIELD OVERWRITE deleted_at ON bbs_board TYPE option<datetime> DEFAULT none;
DEFINE FIELD OVERWRITE is_deleted ON bbs_board COMPUTED !!deleted_at;
DEFINE FIELD OVERWRITE order ON bbs_board TYPE int;
DEFINE FIELD OVERWRITE faction ON bbs_board TYPE option<record<faction>> REFERENCE;
DEFINE FIELD OVERWRITE board_id ON bbs_board TYPE string COMPUTED string::concat(faction.name ?? '', order);
DEFINE FIELD OVERWRITE locks ON bbs_board TYPE object FLEXIBLE;
DEFINE FIELD OVERWRITE next_id ON bbs_board TYPE int DEFAULT 1;

-- BBS System: Posts
DEFINE TABLE OVERWRITE bbs_post SCHEMAFULL;
DEFINE FIELD OVERWRITE board ON bbs_post TYPE record<bbs_board> REFERENCE;
DEFINE FIELD OVERWRITE title ON bbs_post TYPE string;
DEFINE FIELD OVERWRITE content ON bbs_post TYPE string;
DEFINE FIELD OVERWRITE created_at ON bbs_post TYPE datetime READONLY DEFAULT ALWAYS time::now();
DEFINE FIELD OVERWRITE updated_at ON bbs_post TYPE datetime READONLY VALUE time::now();
DEFINE FIELD OVERWRITE deleted_at ON bbs_post TYPE option<datetime> DEFAULT none;
DEFINE FIELD OVERWRITE is_deleted ON bbs_post COMPUTED !!deleted_at;
DEFINE FIELD OVERWRITE acting_as ON bbs_post TYPE record<actor> REFERENCE;

-- Info System - Folders
DEFINE TABLE OVERWRITE textfolder SCHEMAFULL;

DEFINE FIELD OVERWRITE target ON textfolder TYPE record<user|pc|theme|faction|location|plot|scene> REFERENCE;
DEFINE FIELD OVERWRITE name ON textfolder TYPE string;
DEFINE FIELD OVERWRITE locked ON textfolder TYPE bool DEFAULT FALSE;

DEFINE INDEX OVERWRITE textfolder_unique ON textfolder FIELDS target,name UNIQUE CONCURRENTLY;

-- Info System - Text files
DEFINE TABLE OVERWRITE textfile SCHEMAFULL;
DEFINE FIELD OVERWRITE folder ON textfile TYPE record<textfolder> REFERENCE;
DEFINE FIELD OVERWRITE name ON textfile TYPE string;
DEFINE FIELD OVERWRITE name_lower ON textfile TYPE string READONLY VALUE $name.lowercase();
DEFINE FIELD OVERWRITE author ON textfile TYPE record<user> REFERENCE;
DEFINE FIELD OVERWRITE created_at ON textfile TYPE datetime READONLY DEFAULT ALWAYS time::now();
DEFINE FIELD OVERWRITE updated_at ON textfile TYPE datetime READONLY VALUE time::now();
DEFINE FIELD OVERWRITE approved_at ON textfile TYPE option<datetime> DEFAULT none;
DEFINE FIELD OVERWRITE is_approved ON textfile COMPUTED !!approved_at;

DEFINE INDEX OVERWRITE name_lower_unique ON textfile FIELDS folder,name_lower UNIQUE CONCURRENTLY;

-- Info System - Computed Fields
DEFINE FIELD OVERWRITE files ON textfolder COMPUTED (<~textfile ?? []);
DEFINE FIELD OVERWRITE textfolders ON user COMPUTED object::from_entries((<~textfolder ?? []).map(|$f| [$f.name, object::from_entries($f.map(|$fi| [$fi.name, $fi]))]));
DEFINE FIELD OVERWRITE textfolders ON pc COMPUTED object::from_entries((<~textfolder ?? []).map(|$f| [$f.name, object::from_entries($f.map(|$fi| [$fi.name, $fi]))]));
DEFINE FIELD OVERWRITE textfolders ON theme COMPUTED object::from_entries((<~textfolder ?? []).map(|$f| [$f.name, object::from_entries($f.map(|$fi| [$fi.name, $fi]))]));
DEFINE FIELD OVERWRITE textfolders ON faction COMPUTED object::from_entries((<~textfolder ?? []).map(|$f| [$f.name, object::from_entries($f.map(|$fi| [$fi.name, $fi]))]));
DEFINE FIELD OVERWRITE textfolders ON location COMPUTED object::from_entries((<~textfolder ?? []).map(|$f| [$f.name, object::from_entries($f.map(|$fi| [$fi.name, $fi]))]));
DEFINE FIELD OVERWRITE textfolders ON plot COMPUTED object::from_entries((<~textfolder ?? []).map(|$f| [$f.name, object::from_entries($f.map(|$fi| [$fi.name, $fi]))]));
DEFINE FIELD OVERWRITE textfolders ON scene COMPUTED object::from_entries((<~textfolder ?? []).map(|$f| [$f.name, object::from_entries($f.map(|$fi| [$fi.name, $fi]))]));
