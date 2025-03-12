module ai_vault_tp_v526::ai_vault_tm_v526 {
    use std::signer;
    use aptos_framework::coin::{Self, Coin};
    use aptos_framework::aptos_coin::AptosCoin;
    use liquidswap_v05::router;
    use liquidswap_v05::curves::Uncorrelated;
    use liquidswap_v05::curves::Stable;
    use std::type_info::{Self, TypeInfo};
    use std::vector;
    use std::bcs;
    use liquidswap_v05::coin_helper;
    use aptos_framework::table::{Self, Table};
    use aptos_framework::timestamp;
    use aptos_framework::event::{Self, EventHandle};
    use aptos_framework::account;

    // Contract address constant
    const VAULT_ADDRESS: address = @ai_vault_tp_v526;

    // Add resource account address constant
    const RESOURCE_ACCOUNT: address = VAULT_ADDRESS;

    // Resource account seed and configuration constants
    const MODULE_ADDRESS: address = VAULT_ADDRESS;
    
    // Create full module path by combining address and module name
    fun get_source_module(): vector<u8> {
        let module_info = type_info::type_of<Vault>();
        let source = vector::empty<u8>();
        vector::append(&mut source, bcs::to_bytes(&type_info::account_address(&module_info)));
        vector::push_back(&mut source, 0x3A);  // Add ':' character
        vector::push_back(&mut source, 0x3A);  // Add ':' character
        vector::append(&mut source, type_info::module_name(&module_info));
        source
    }

    // Get vault seed using module name
    fun get_vault_seed(): vector<u8> {
        let module_info = type_info::type_of<Vault>();
        type_info::module_name(&module_info)
    }

    const MAX_DEPOSIT_AMOUNT: u64 = 1000000000000; // 10K APT maximum deposit
    const MAX_SWAP_AMOUNT: u64 = 1000000000000;    // 10K APT maximum swap
    const DEFAULT_WITHDRAW_DELAY: u64 = 300;        // 5 minutes in seconds
    const DEFAULT_RESERVE_UPDATE_THRESHOLD: u64 = 20; // 20% maximum price change
    const DEFAULT_RESERVE_UPDATE_TIME: u64 = 300;  // 5 minutes in seconds

    // Error codes
    const ENOT_ADMIN: u64 = 1;
    const EINSUFFICIENT_SHARES: u64 = 2;
    const ENO_DEPOSIT: u64 = 3;
    const EZERO_DEPOSIT: u64 = 4;
    const ETOKEN_NOT_FOUND: u64 = 5;
    const ETOKEN_ALREADY_EXISTS: u64 = 6;
    const ERESERVES_NOT_FOUND: u64 = 7;
    const EINVALID_TOKEN_ORDER: u64 = 8;
    const EARITHMETIC_OVERFLOW: u64 = 9;
    const EVAULT_DISABLED: u64 = 10;
    const EWITHDRAW_TOO_EARLY: u64 = 11;
    const EINVALID_RESERVE_UPDATE: u64 = 12;
    const EINSUFFICIENT_APT: u64 = 13;
    const EDEPOSIT_TOO_LARGE: u64 = 14;
    const ESWAP_TOO_LARGE: u64 = 15;
    const EZERO_SHARES: u64 = 16;
    const EINVALID_WITHDRAW_AMOUNT: u64 = 17;
    const ENOT_INITIALIZED: u64 = 18;
    const ETOKEN_NOT_REGISTERED: u64 = 19;
    const ELIQUIDITY_POOL_NOT_FOUND: u64 = 20;
    const EINSUFFICIENT_VAULT_APT: u64 = 21;
    const ESWAP_FAILED: u64 = 22;
    const ESWAP_ROUTER_ERROR: u64 = 25;
    const ETOKEN_REGISTRATION_FAILED: u64 = 26;
    const EREGISTER_FAILED: u64 = 27;
    const ERESOURCE_SIGNER_ERROR: u64 = 28;
    const ERESERVES_NOT_UPDATED: u64 = 29;
    const EINVALID_FEE: u64 = 30;
    const EINVALID_FEE_WALLET: u64 = 31;
    const EINVALID_CURVE_TYPE: u64 = 32;

    // Constants for calculations and limits
    const MAX_U128: u128 = 340282366920938463463374607431768211455;
    const PRECISION_MULTIPLIER: u128 = 1000000000000; // 12 decimals for calculation
    const CALCULATION_DECIMALS: u8 = 12;
    const STANDARD_DECIMALS: u8 = 8;  // APT decimals, also used for total value and shares
    const DECIMAL_SCALING: u128 = 10000; // 10^(CALCULATION_DECIMALS - STANDARD_DECIMALS) = 10^4

    // Token reserve information structure
    struct TokenReserve has store {
        reserve_x: u128,  // APT amount in pool
        reserve_y: u128,  // Token amount in pool
        last_update_time: u64,  // Last time reserves were updated
        decimals: u8,  // Token decimals
        token_address: address,  // Token contract address
        token_module_name: vector<u8>,  // Token module name
        token_struct_name: vector<u8>,  // Token struct name
        check_update_time: bool,  // Whether to check update time for this token
        curve_type: u64,  // 0 for Stable, 1 for Uncorrelated
    }

    // Event structures for tracking operations
    struct DepositEvent has drop, store {
        user: address,
        amount: u128,
        shares: u128,
        timestamp: u64,
        vault_total_shares: u128,
        vault_total_value: u128,
        vault_total_apt: u128,
        user_amount: u128,    // Add user amount (same as amount for deposit)
        fee_amount: u128,     // Add fee amount (always 0 for deposit)
        source_module: vector<u8>  // Add source module information
    }

    struct WithdrawEvent has drop, store {
        user: address,
        shares: u128,
        apt_amount: u128,
        timestamp: u64,
        vault_total_shares: u128,
        vault_total_value: u128,
        vault_total_apt: u128,
        user_amount: u128,    // Add actual amount user receives
        fee_amount: u128,     // Add fee amount charged
        source_module: vector<u8>  // Add source module information
    }

    struct SwapEvent has drop, store {
        token_type: TypeInfo,
        is_apt_to_token: bool,
        amount_in: u128,
        amount_out: u128,
        timestamp: u64,
        vault_total_shares: u128,
        vault_total_value: u128,
        vault_total_apt: u128,
        curve_type: u64,  // 0 for Stable, 1 for Uncorrelated
        source_module: vector<u8>  // Add source module information
    }

    // Main vault structure for managing assets and operations
    struct Vault has key {
        coins: Coin<AptosCoin>,  // APT holdings
        token_reserves: Table<TypeInfo, TokenReserve>,  // Token reserve info
        token_balances: Table<TypeInfo, u128>,  // Current token balances
        token_types: vector<TypeInfo>,  // List of all swapped tokens
        admin: address,  // Admin address
        total_shares: u128,  // Total shares issued
        vault_enabled: bool,  // Vault operation status
        withdraw_delay: u64,  // Minimum time between deposit and withdrawal
        reserve_update_threshold: u64,  // Maximum allowed reserve update percentage
        reserve_update_time: u64,  // Maximum allowed time since last reserve update
        fee: u64,                // Fee in basis points (1 = 0.01%, max 500 = 5%)
        fee_wallet: address,     // Address to receive fees
        deposit_events: EventHandle<DepositEvent>,
        withdraw_events: EventHandle<WithdrawEvent>,
        swap_events: EventHandle<SwapEvent>
    }

    // User share record structure
    struct UserShares has key {
        shares: Table<address, UserShareInfo>  // User share balances
    }

    // User share information structure
    struct UserShareInfo has store {
        amount: u128,  // Share amount
        last_deposit_time: u64  // Last deposit timestamp
    }

    // Add resource account signer storage
    struct VaultResource has key {
        signer_cap: account::SignerCapability
    }

    // Add helper function to get resource account address
    fun get_resource_account_address(): address {
        account::create_resource_address(&RESOURCE_ACCOUNT, get_vault_seed())
    }

    // Initialize vault with default settings
    public entry fun initialize(admin: &signer) {
        let admin_addr = signer::address_of(admin);
        
        // Create resource account with a unique seed
        let (resource_signer, signer_cap) = account::create_resource_account(admin, get_vault_seed());
        
        // Store signer capability in resource account instead of admin
        move_to(&resource_signer, VaultResource {
            signer_cap
        });

        // Register APT coin for resource account
        if (!coin::is_account_registered<AptosCoin>(RESOURCE_ACCOUNT)) {
            coin::register<AptosCoin>(&resource_signer);
        };

        // Initialize vault under resource account
        move_to(&resource_signer, Vault {
            coins: coin::zero<AptosCoin>(),
            token_reserves: table::new(),
            token_balances: table::new(),
            token_types: vector::empty<TypeInfo>(),
            admin: admin_addr,
            total_shares: 0,
            vault_enabled: false,
            withdraw_delay: DEFAULT_WITHDRAW_DELAY,
            reserve_update_threshold: DEFAULT_RESERVE_UPDATE_THRESHOLD,
            reserve_update_time: DEFAULT_RESERVE_UPDATE_TIME,
            fee: 1,                 // Default fee 0.01%
            fee_wallet: admin_addr, // Default fee wallet is admin
            deposit_events: account::new_event_handle(&resource_signer),
            withdraw_events: account::new_event_handle(&resource_signer),
            swap_events: account::new_event_handle(&resource_signer)
        });
        
        move_to(&resource_signer, UserShares {
            shares: table::new()
        });
    }

    // Enable or disable vault operations
    public entry fun set_vault_enabled(admin: &signer, enabled: bool) acquires Vault {
        assert!(is_initialized(), ENOT_INITIALIZED);
        let admin_addr = signer::address_of(admin);
        let resource_addr = get_resource_account_address();
        let vault = borrow_global_mut<Vault>(resource_addr);
        assert!(admin_addr == vault.admin, ENOT_ADMIN);
        vault.vault_enabled = enabled;
    }

    // Set minimum delay between deposit and withdrawal
    public entry fun set_withdraw_delay(admin: &signer, delay: u64) acquires Vault {
        let admin_addr = signer::address_of(admin);
        let resource_addr = get_resource_account_address();
        let vault = borrow_global_mut<Vault>(resource_addr);
        assert!(admin_addr == vault.admin, ENOT_ADMIN);
        vault.withdraw_delay = delay;
    }

    // Set maximum allowed percentage change for reserve updates
    public entry fun set_reserve_update_threshold(admin: &signer, threshold: u64) acquires Vault {
        let admin_addr = signer::address_of(admin);
        let resource_addr = get_resource_account_address();
        let vault = borrow_global_mut<Vault>(resource_addr);
        assert!(admin_addr == vault.admin, ENOT_ADMIN);
        assert!(threshold <= 100, EINVALID_RESERVE_UPDATE); // Max 100%
        vault.reserve_update_threshold = threshold;
    }

    // Add function to set reserve update time threshold
    public entry fun set_reserve_update_time(admin: &signer, time: u64) acquires Vault {
        let admin_addr = signer::address_of(admin);
        let resource_addr = get_resource_account_address();
        let vault = borrow_global_mut<Vault>(resource_addr);
        assert!(admin_addr == vault.admin, ENOT_ADMIN);
        vault.reserve_update_time = time;
    }

    // Internal function for updating reserves
    fun internal_update_reserves<TokenType>(
        vault: &mut Vault,
        admin_addr: address,
        check_threshold: bool,
        curve_type: u64
    ) {
        assert!(admin_addr == vault.admin, ENOT_ADMIN);
        
        let token_type = type_info::type_of<TokenType>();
        assert!(table::contains(&vault.token_reserves, token_type), ETOKEN_NOT_FOUND);
        
        let (reserve_x, reserve_y) = if (curve_type == 0) {
            router::get_reserves_size<AptosCoin, TokenType, Stable>()
        } else {
            router::get_reserves_size<AptosCoin, TokenType, Uncorrelated>()
        };
        
        let reserve_info = table::borrow_mut(&mut vault.token_reserves, token_type);
        
        // Convert to u128
        let new_reserve_x = (reserve_x as u128);
        let new_reserve_y = (reserve_y as u128);
        
        // Check if update is within threshold when required
        if (check_threshold && reserve_info.reserve_x > 0) {
            let x_change = if (new_reserve_x > reserve_info.reserve_x) {
                ((new_reserve_x - reserve_info.reserve_x) * 100) / reserve_info.reserve_x
            } else {
                ((reserve_info.reserve_x - new_reserve_x) * 100) / reserve_info.reserve_x
            };
            assert!(x_change <= (vault.reserve_update_threshold as u128), EINVALID_RESERVE_UPDATE);
        };
        
        // Update reserves
        reserve_info.reserve_x = new_reserve_x;
        reserve_info.reserve_y = new_reserve_y;
        reserve_info.last_update_time = timestamp::now_seconds();
        reserve_info.curve_type = curve_type;
    }

    // Update token reserves with threshold check
    public entry fun update_reserves_for_token<TokenType>(admin: &signer, curve_type: u64) acquires Vault {
        validate_curve_type(curve_type);
        let resource_addr = get_resource_account_address();
        let vault = borrow_global_mut<Vault>(resource_addr);
        internal_update_reserves<TokenType>(vault, signer::address_of(admin), true, curve_type);
    }

    // Update token reserves without threshold check
    public entry fun update_reserves_for_token_wc<TokenType>(admin: &signer, curve_type: u64) acquires Vault {
        validate_curve_type(curve_type);
        let resource_addr = get_resource_account_address();
        let vault = borrow_global_mut<Vault>(resource_addr);
        internal_update_reserves<TokenType>(vault, signer::address_of(admin), false, curve_type);
    }

    // Get token reserves update status
    #[view]
    public fun get_token_reserves_status<TokenType>(): (u128, u128, u128, u128, u64, u64) acquires Vault {
        let resource_addr = get_resource_account_address();
        let vault = borrow_global<Vault>(resource_addr);
        let token_type = type_info::type_of<TokenType>();
        assert!(table::contains(&vault.token_reserves, token_type), ETOKEN_NOT_FOUND);
        
        let reserve_info = table::borrow(&vault.token_reserves, token_type);
        let (current_x, current_y) = if (reserve_info.curve_type == 0) {
            router::get_reserves_size<AptosCoin, TokenType, Stable>()
        } else {
            router::get_reserves_size<AptosCoin, TokenType, Uncorrelated>()
        };
        
        (
            reserve_info.reserve_x,  // Stored reserve x
            reserve_info.reserve_y,  // Stored reserve y
            (current_x as u128),     // Current reserve x
            (current_y as u128),     // Current reserve y
            reserve_info.last_update_time,  // Last update time
            reserve_info.curve_type   // Curve type
        )
    }

    // Calculate token price with high precision (12 decimals)
    fun calculate_token_price(reserve_x: u128, reserve_y: u128): u128 {
        assert!(reserve_y > 0, ERESERVES_NOT_FOUND);
        
        // Check for multiplication overflow
        assert!((reserve_x * PRECISION_MULTIPLIER) <= MAX_U128, EARITHMETIC_OVERFLOW);
        
        // Calculate price with 12 decimals precision
        let price = (reserve_x * PRECISION_MULTIPLIER) / reserve_y;
        assert!(price <= MAX_U128, EARITHMETIC_OVERFLOW);
        
        price
    }

    // Get token price in APT for any curve type
    #[view]
    public fun get_token_price_in_apt<TokenType>(curve_type: u64): (u128, u8) {
        let (reserve_x, reserve_y) = if (curve_type == 0) {
            router::get_reserves_size<AptosCoin, TokenType, Stable>()
        } else {
            router::get_reserves_size<AptosCoin, TokenType, Uncorrelated>()
        };
        
        let price = calculate_token_price((reserve_x as u128), (reserve_y as u128));
        (price, CALCULATION_DECIMALS)  // Return price with 12 decimals for precision
    }

    // Compare two byte vectors lexicographically
    fun compare_bytes(a: &vector<u8>, b: &vector<u8>): bool {
        let len_a = vector::length(a);
        let len_b = vector::length(b);
        let i = 0;
        
        while (i < len_a && i < len_b) {
            let byte_a = *vector::borrow(a, i);
            let byte_b = *vector::borrow(b, i);
            if (byte_a != byte_b) {
                return byte_a < byte_b
            };
            i = i + 1;
        };
        len_a < len_b
    }

    // Compare token types for consistent ordering
    fun is_token_smaller<TokenType>(): bool {
        let token_info = type_info::type_of<TokenType>();
        let apt_info = type_info::type_of<AptosCoin>();
        
        // Debug assertions
        assert!(type_info::account_address(&token_info) != @0x0, ETOKEN_NOT_FOUND);
        assert!(type_info::account_address(&apt_info) != @0x0, ETOKEN_NOT_FOUND);

        // Compare module names first
        let token_module = type_info::module_name(&token_info);
        let apt_module = type_info::module_name(&apt_info);
        
        if (token_module != apt_module) {
            return compare_bytes(&token_module, &apt_module)
        };

        // If module names are equal, compare struct names
        let token_struct = type_info::struct_name(&token_info);
        let apt_struct = type_info::struct_name(&apt_info);
        
        compare_bytes(&token_struct, &apt_struct)
    }

    // Get reserves for token pair with error handling
    fun get_reserves_for_token<TokenType>(): (u128, u128) {
        // Use Liquidswap's coin_helper to determine token order
        let is_coin_x = coin_helper::is_sorted<TokenType, AptosCoin>();
        
        let (reserve_x, reserve_y) = if (is_coin_x) {
            let (reserve_y, reserve_x) = router::get_reserves_size<TokenType, AptosCoin, Uncorrelated>();
            ((reserve_x as u128), (reserve_y as u128))
        } else {
            let (x, y) = router::get_reserves_size<AptosCoin, TokenType, Uncorrelated>();
            ((x as u128), (y as u128))
        };

        // Validate reserves
        assert!(reserve_x > 0, ERESERVES_NOT_FOUND);
        assert!(reserve_y > 0, ERESERVES_NOT_FOUND);

        (reserve_x, reserve_y)
    }

    // Convert address to u256 for calculations
    fun to_u256(addr: address): u256 {
        let bytes = bcs::to_bytes(&addr);
        let value = 0u256;
        let i = 0;
        let len = vector::length(&bytes);
        while (i < len) {
            let byte = (*vector::borrow(&bytes, i) as u256);
            value = value << 8;
            value = value + byte;
            i = i + 1;
        };
        value
    }

    // Internal function to calculate total vault value
    fun internal_get_vault_total_value(vault: &Vault): u128 {
        let total_value = (coin::value(&vault.coins) as u128);
        
        let i = 0;
        let len = vector::length(&vault.token_types);
        
        while (i < len) {
            let token_type = *vector::borrow(&vault.token_types, i);
            let token_reserve = table::borrow(&vault.token_reserves, token_type);
            let token_balance = table::borrow(&vault.token_balances, token_type);
            
            if (*token_balance > 0) {
                // Calculate token value in APT using reserves
                // First check for multiplication overflow
                assert!((token_reserve.reserve_x * *token_balance) <= MAX_U128, EARITHMETIC_OVERFLOW);
                
                // Calculate: (reserve_x * token_balance) / reserve_y
                // This gives us the APT value (8 decimals) of the token balance
                let token_value = (token_reserve.reserve_x * *token_balance) / token_reserve.reserve_y;
                
                total_value = total_value + token_value;
                // Check for addition overflow
                assert!(total_value <= MAX_U128, EARITHMETIC_OVERFLOW);
            };
            i = i + 1;
        };
        
        total_value
    }

    // Update public function to use internal function
    #[view]
    public fun get_vault_total_value(): u128 acquires Vault {
        let resource_addr = get_resource_account_address();
        let vault = borrow_global<Vault>(resource_addr);
        internal_get_vault_total_value(vault)
    }

    // Helper function to calculate shares
    fun calculate_shares(
        amount: u64,
        total_value: u128,
        total_shares: u128
    ): u128 {
        let amount_u128 = (amount as u128);
        if (total_shares == 0) {
            amount_u128
        } else {
            // Check for multiplication overflow
            assert!((amount_u128 * total_shares) <= MAX_U128, EARITHMETIC_OVERFLOW);
            
            // Multiply first then divide to maintain precision
            (amount_u128 * total_shares) / total_value
        }
    }

    // Helper function to calculate withdrawal amount
    fun calculate_withdrawal_amount(
        shares: u128,
        total_shares: u128,
        total_value: u128
    ): u128 {
        assert!(total_shares > 0, EZERO_DEPOSIT);
        // Check for multiplication overflow
        assert!((total_value * shares) <= MAX_U128, EARITHMETIC_OVERFLOW);
        
        // Multiply first then divide to maintain precision
        (total_value * shares) / total_shares
    }

    // Add function to check if reserves are up to date
    fun check_reserves_update_time(vault: &Vault): bool {
        let current_time = timestamp::now_seconds();
        let i = 0;
        let len = vector::length(&vault.token_types);
        
        while (i < len) {
            let token_type = *vector::borrow(&vault.token_types, i);
            let balance = *table::borrow(&vault.token_balances, token_type);
            if (balance > 0) {
                let reserve_info = table::borrow(&vault.token_reserves, token_type);
                if (reserve_info.check_update_time && 
                    (current_time - reserve_info.last_update_time) > vault.reserve_update_time) {
                    return false
                };
            };
            i = i + 1;
        };
        true
    }

    // Update deposit function
    public entry fun deposit(user: &signer, amount: u64) acquires Vault, UserShares {
        let resource_addr = get_resource_account_address();
        let vault = borrow_global_mut<Vault>(resource_addr);
        
        // Check reserves update time first
        assert!(check_reserves_update_time(vault), ERESERVES_NOT_UPDATED);
        
        assert!(vault.vault_enabled, EVAULT_DISABLED);
        assert!(amount > 0, EZERO_DEPOSIT);
        assert!(amount <= MAX_DEPOSIT_AMOUNT, EDEPOSIT_TOO_LARGE);
        
        let total_value = internal_get_vault_total_value(vault);
        let new_shares = calculate_shares(amount, total_value, vault.total_shares);
        assert!(new_shares > 0, EZERO_SHARES);
        
        let deposit_coins = coin::withdraw<AptosCoin>(user, amount);
        coin::merge(&mut vault.coins, deposit_coins);
        vault.total_shares = vault.total_shares + new_shares;
        
        // Update user shares with timestamp
        let user_addr = signer::address_of(user);
        let user_shares = borrow_global_mut<UserShares>(resource_addr);
        
        if (!table::contains(&user_shares.shares, user_addr)) {
            table::add(&mut user_shares.shares, user_addr, UserShareInfo {
                amount: new_shares,
                last_deposit_time: timestamp::now_seconds()
            });
        } else {
            let user_share_info = table::borrow_mut(&mut user_shares.shares, user_addr);
            user_share_info.amount = user_share_info.amount + new_shares;
            user_share_info.last_deposit_time = timestamp::now_seconds();
        };

        // Calculate all values before emitting events to avoid borrow conflicts
        let total_value = internal_get_vault_total_value(vault);
        let current_apt = coin::value(&vault.coins);
        let current_shares = vault.total_shares;

        event::emit_event(&mut vault.deposit_events, DepositEvent {
            user: signer::address_of(user),
            amount: (amount as u128),
            shares: new_shares,
            timestamp: timestamp::now_seconds(),
            vault_total_shares: current_shares,
            vault_total_value: total_value,
            vault_total_apt: (current_apt as u128),
            user_amount: (amount as u128),  // Same as amount for deposit
            fee_amount: 0,                   // No fee for deposit
            source_module: get_source_module()  // Add module name
        });
    }

    // Update withdraw function
    public entry fun withdraw(user: &signer, shares: u128) acquires Vault, UserShares {
        let resource_addr = get_resource_account_address();
        let vault = borrow_global_mut<Vault>(resource_addr);
        
        // Check reserves update time first
        assert!(check_reserves_update_time(vault), ERESERVES_NOT_UPDATED);
        
        assert!(vault.vault_enabled, EVAULT_DISABLED);
        assert!(shares > 0, EZERO_SHARES);
        
        let user_addr = signer::address_of(user);
        let user_shares = borrow_global<UserShares>(resource_addr);
        
        assert!(table::contains(&user_shares.shares, user_addr), ENO_DEPOSIT);
        
        let user_share_info = table::borrow(&user_shares.shares, user_addr);
        assert!(user_share_info.amount >= shares, EINSUFFICIENT_SHARES);
        
        // Check withdraw delay
        let current_time = timestamp::now_seconds();
        assert!(current_time >= user_share_info.last_deposit_time + vault.withdraw_delay, EWITHDRAW_TOO_EARLY);
        
        // Calculate total withdrawal amount from shares
        let total_apt = calculate_withdrawal_amount(shares, vault.total_shares, internal_get_vault_total_value(vault));
        let apt_amount = (total_apt as u64);
        
        // Check available APT balance
        let available_apt = (coin::value(&vault.coins) as u128);
        assert!(available_apt >= (apt_amount as u128), EINSUFFICIENT_APT);
        
        // Calculate fee and user amounts
        let fee_amount = ((apt_amount as u128) * (vault.fee as u128)) / 10000;
        let user_amount = apt_amount - (fee_amount as u64);
        
        // Extract fee coins and user coins separately
        let fee_coins = coin::extract(&mut vault.coins, (fee_amount as u64));
        let user_coins = coin::extract(&mut vault.coins, user_amount);
        
        // Send fee to fee wallet
        coin::deposit(vault.fee_wallet, fee_coins);
        // Send user amount to user
        coin::deposit(user_addr, user_coins);
        
        // Update shares
        vault.total_shares = vault.total_shares - shares;
        let user_shares = borrow_global_mut<UserShares>(resource_addr);
        let user_share_info = table::borrow_mut(&mut user_shares.shares, user_addr);
        user_share_info.amount = user_share_info.amount - shares;

        // Calculate all values before emitting events to avoid borrow checker errors
        let total_value = internal_get_vault_total_value(vault);
        let current_apt = coin::value(&vault.coins);
        let current_shares = vault.total_shares;

        event::emit_event(&mut vault.withdraw_events, WithdrawEvent {
            user: user_addr,
            shares,
            apt_amount: total_apt,
            timestamp: timestamp::now_seconds(),
            vault_total_shares: current_shares,
            vault_total_value: total_value,
            vault_total_apt: (current_apt as u128),
            user_amount: (user_amount as u128),  // Amount after fee deduction
            fee_amount,                           // Fee amount charged
            source_module: get_source_module()  // Add module name
        });
    }

    // Update get_max_withdrawable_apt function
    #[view]
    public fun get_max_withdrawable_apt(user_addr: address): (u128, u64) acquires Vault, UserShares {
        let resource_addr = get_resource_account_address();
        let vault = borrow_global<Vault>(resource_addr);
        let user_shares = borrow_global<UserShares>(resource_addr);
        
        // Check if user has any shares
        if (!table::contains(&user_shares.shares, user_addr)) {
            return (0, 0)
        };
        
        let user_share_info = table::borrow(&user_shares.shares, user_addr);
        let current_time = timestamp::now_seconds();
        
        // Check if withdrawal is allowed based on time delay
        if (current_time < user_share_info.last_deposit_time + vault.withdraw_delay) {
            return (0, user_share_info.last_deposit_time + vault.withdraw_delay)
        };
        
        let total_value = internal_get_vault_total_value(vault);
        if (total_value == 0 || vault.total_shares == 0) {
            return (0, 0)
        };
        
        // Calculate user's withdrawable value
        let user_value = calculate_withdrawal_amount(
            user_share_info.amount,  // User's shares
            vault.total_shares,      // Total shares
            total_value             // Total vault value
        );
        
        // Check available APT balance
        let available_apt = (coin::value(&vault.coins) as u128);
        let max_apt = if (user_value > available_apt) {
            available_apt
        } else {
            user_value
        };
        
        (max_apt, 0)
    }

    // Add resource signer getter function with checks
    fun get_resource_signer(): signer acquires VaultResource {
        let resource_addr = get_resource_account_address();
        assert!(exists<VaultResource>(resource_addr), ENOT_INITIALIZED);
        
        let signer_cap = &borrow_global<VaultResource>(resource_addr).signer_cap;
        account::create_signer_with_capability(signer_cap)
    }

    // Add curve type validation to swap functions
    fun validate_curve_type(curve_type: u64) {
        assert!(curve_type == 0 || curve_type == 1, EINVALID_CURVE_TYPE);
    }

    // Update swap_apt_to_token_v05 to use resource account
    public entry fun swap_apt_to_token_v05<TokenType>(
        admin: &signer,
        amount: u64,
        min_amount_out: u64,
        curve_type: u64
    ) acquires Vault, VaultResource {
        validate_curve_type(curve_type);
        let resource_addr = get_resource_account_address();
        let vault = borrow_global_mut<Vault>(resource_addr);
        
        // Check reserves update time first
        //assert!(check_reserves_update_time(vault), ERESERVES_NOT_UPDATED);
        
        // 1. Check vault enabled
        if (!vault.vault_enabled) {
            abort EVAULT_DISABLED
        };

        // 2. Check admin
        if (signer::address_of(admin) != vault.admin) {
            abort ENOT_ADMIN
        };

        // 3. Check amount
        if (amount > MAX_SWAP_AMOUNT) {
            abort ESWAP_TOO_LARGE
        };

        // 4. Check vault APT balance
        if (coin::value(&vault.coins) < amount) {
            abort EINSUFFICIENT_VAULT_APT
        };

        // 5. Check token registration and register if needed
        let resource_signer = get_resource_signer();
        if (!coin::is_account_registered<TokenType>(resource_addr)) {
            coin::register<TokenType>(&resource_signer);
            assert!(coin::is_account_registered<TokenType>(resource_addr), ETOKEN_REGISTRATION_FAILED);
        };

        // 6. Check liquidity pool
        let (reserve_x, reserve_y) = if (curve_type == 0) {
            router::get_reserves_size<AptosCoin, TokenType, Stable>()
        } else {
            router::get_reserves_size<AptosCoin, TokenType, Uncorrelated>()
        };
        if (reserve_x == 0 || reserve_y == 0) {
            abort ELIQUIDITY_POOL_NOT_FOUND
        };

        // 7. Perform swap
        let apt_coins = coin::extract(&mut vault.coins, amount);
        let token_coins = if (curve_type == 0) {
            router::swap_exact_coin_for_coin<AptosCoin, TokenType, Stable>(
                apt_coins,
                min_amount_out
            )
        } else {
            router::swap_exact_coin_for_coin<AptosCoin, TokenType, Uncorrelated>(
                apt_coins,
                min_amount_out
            )
        };

        // 8. Check swap result
        if (coin::value(&token_coins) < min_amount_out) {
            abort ESWAP_FAILED
        };

        let token_type = type_info::type_of<TokenType>();
        let token_amount = (coin::value(&token_coins) as u128);

        if (!table::contains(&vault.token_reserves, token_type)) {
            let (reserve_x, reserve_y) = if (curve_type == 0) {
                router::get_reserves_size<AptosCoin, TokenType, Stable>()
            } else {
                router::get_reserves_size<AptosCoin, TokenType, Uncorrelated>()
            };
            table::add(&mut vault.token_reserves, token_type, TokenReserve {
                reserve_x: (reserve_x as u128),
                reserve_y: (reserve_y as u128),
                last_update_time: timestamp::now_seconds(),
                decimals: coin::decimals<TokenType>(),
                token_address: type_info::account_address(&token_type),
                token_module_name: type_info::module_name(&token_type),
                token_struct_name: type_info::struct_name(&token_type),
                check_update_time: true,
                curve_type
            });
            table::add(&mut vault.token_balances, token_type, token_amount);
            vector::push_back(&mut vault.token_types, token_type);
        } else {
            let token_balance = table::borrow_mut(&mut vault.token_balances, token_type);
            assert!((*token_balance + token_amount) <= MAX_U128, EARITHMETIC_OVERFLOW);
            *token_balance = *token_balance + token_amount;
            
            let (reserve_x, reserve_y) = if (curve_type == 0) {
                router::get_reserves_size<AptosCoin, TokenType, Stable>()
            } else {
                router::get_reserves_size<AptosCoin, TokenType, Uncorrelated>()
            };
            let reserve_info = table::borrow_mut(&mut vault.token_reserves, token_type);
            reserve_info.reserve_x = (reserve_x as u128);
            reserve_info.reserve_y = (reserve_y as u128);
            reserve_info.last_update_time = timestamp::now_seconds();
            reserve_info.curve_type = curve_type;
        };

        // Get all vault values before emitting event to prevent multiple borrows
        let total_value = internal_get_vault_total_value(vault);
        let current_apt = coin::value(&vault.coins);
        let current_shares = vault.total_shares;

        event::emit_event(&mut vault.swap_events, SwapEvent {
            token_type,
            is_apt_to_token: true,
            amount_in: (amount as u128),
            amount_out: token_amount,
            timestamp: timestamp::now_seconds(),
            vault_total_shares: current_shares,
            vault_total_value: total_value,
            vault_total_apt: (current_apt as u128),
            curve_type,
            source_module: get_source_module()  // Add module name
        });

        coin::deposit(resource_addr, token_coins);
    }

    // Update swap_token_to_apt_v05 to use resource account
    public entry fun swap_token_to_apt_v05<TokenType>(
        admin: &signer,
        amount: u64,
        min_apt_out: u64,
        curve_type: u64
    ) acquires Vault, VaultResource {
        validate_curve_type(curve_type);
        let resource_addr = get_resource_account_address();
        let vault = borrow_global_mut<Vault>(resource_addr);
        
        // Check reserves update time first
        //assert!(check_reserves_update_time(vault), ERESERVES_NOT_UPDATED);
        
        assert!(signer::address_of(admin) == vault.admin, ENOT_ADMIN);
        
        let token_type = type_info::type_of<TokenType>();
        assert!(table::contains(&vault.token_balances, token_type), ETOKEN_NOT_FOUND);
        
        let token_balance = table::borrow_mut(&mut vault.token_balances, token_type);
        assert!(*token_balance >= (amount as u128), EINSUFFICIENT_SHARES);
        *token_balance = *token_balance - (amount as u128);

        // Get resource signer and withdraw tokens
        let resource_signer = get_resource_signer();
        let token_coins = coin::withdraw<TokenType>(&resource_signer, amount);
        
        let apt_coins = if (curve_type == 0) {
            router::swap_exact_coin_for_coin<TokenType, AptosCoin, Stable>(
                token_coins,
                min_apt_out
            )
        } else {
            router::swap_exact_coin_for_coin<TokenType, AptosCoin, Uncorrelated>(
                token_coins,
                min_apt_out
            )
        };
        
        // Get the amount before merging coins
        let apt_amount = coin::value(&apt_coins);
        
        internal_update_reserves<TokenType>(vault, signer::address_of(admin), false, curve_type);
        coin::merge(&mut vault.coins, apt_coins);

        // Calculate vault state before emitting event to avoid borrow conflicts
        let total_value = internal_get_vault_total_value(vault);
        let current_apt = coin::value(&vault.coins);
        let current_shares = vault.total_shares;

        event::emit_event(&mut vault.swap_events, SwapEvent {
            token_type,
            is_apt_to_token: false,
            amount_in: (amount as u128),
            amount_out: (apt_amount as u128),
            timestamp: timestamp::now_seconds(),
            vault_total_shares: current_shares,
            vault_total_value: total_value,
            vault_total_apt: (current_apt as u128),
            curve_type,
            source_module: get_source_module()  // Add module name
        });
    }

    // Get user share amount and last deposit time
    #[view]
    public fun get_user_shares(user_addr: address): (u128, u64) acquires UserShares {
        let resource_addr = get_resource_account_address();
        let shares = &borrow_global<UserShares>(resource_addr).shares;
        if (!table::contains(shares, user_addr)) return (0, 0);
        let info = table::borrow(shares, user_addr);
        (info.amount, info.last_deposit_time)
    }

    // Get comprehensive vault information
    #[view]
    public fun get_vault_info(): (u128, u128, bool, u64, u64, u128, u64, address) acquires Vault {
        let resource_addr = get_resource_account_address();
        let vault = borrow_global<Vault>(resource_addr);
        let total_value = internal_get_vault_total_value(vault);
        
        (
            vault.total_shares,
            (coin::value(&vault.coins) as u128),
            vault.vault_enabled,
            vault.withdraw_delay,
            vault.reserve_update_threshold,
            total_value,
            vault.fee,
            vault.fee_wallet
        )
    }

    // Get token balance and metadata
    #[view]
    public fun get_token_info<TokenType>(): (u128, u8, u64) acquires Vault {
        let resource_addr = get_resource_account_address();
        let vault = borrow_global<Vault>(resource_addr);
        let token_type = type_info::type_of<TokenType>();
        
        if (table::contains(&vault.token_reserves, token_type)) {
            let reserve_info = table::borrow(&vault.token_reserves, token_type);
            let balance = *table::borrow(&vault.token_balances, token_type);
            (balance, reserve_info.decimals, reserve_info.last_update_time)
        } else {
            (0, 0, 0)
        }
    }

    // Get information for all tokens in vault
    #[view]
    public fun get_vault_tokens(): (
        vector<TypeInfo>,
        vector<u128>,
        vector<u8>,
        vector<u64>,
        vector<bool>,
        vector<u64>  // curve types
    ) acquires Vault {
        let resource_addr = get_resource_account_address();
        let vault = borrow_global<Vault>(resource_addr);
        
        let token_types = vector::empty<TypeInfo>();
        let balances = vector::empty<u128>();
        let decimals = vector::empty<u8>();
        let last_updates = vector::empty<u64>();
        let check_updates = vector::empty<bool>();
        let curve_types = vector::empty<u64>();
        
        let i = 0;
        let len = vector::length(&vault.token_types);
        
        while (i < len) {
            let token_type = *vector::borrow(&vault.token_types, i);
            let reserve_info = table::borrow(&vault.token_reserves, token_type);
            let balance = table::borrow(&vault.token_balances, token_type);
            
            vector::push_back(&mut token_types, token_type);
            vector::push_back(&mut balances, *balance);
            vector::push_back(&mut decimals, reserve_info.decimals);
            vector::push_back(&mut last_updates, reserve_info.last_update_time);
            vector::push_back(&mut check_updates, reserve_info.check_update_time);
            vector::push_back(&mut curve_types, reserve_info.curve_type);
            
            i = i + 1;
        };
        
        (token_types, balances, decimals, last_updates, check_updates, curve_types)
    }

    // Get APT and token reserves for any curve type
    #[view]
    public fun get_apt_token_reserves_size<TokenType>(curve_type: u64): (u128, u128) {
        let (reserve_x, reserve_y) = if (curve_type == 0) {
            router::get_reserves_size<AptosCoin, TokenType, Stable>()
        } else {
            router::get_reserves_size<AptosCoin, TokenType, Uncorrelated>()
        };
        
        ((reserve_x as u128), (reserve_y as u128))
    }

    // Get detailed token information including address and names
    #[view]
    public fun get_token_full_info<TokenType>(): (address, vector<u8>, vector<u8>, u128, u128, u64, u64) acquires Vault {
        let resource_addr = get_resource_account_address();
        let vault = borrow_global<Vault>(resource_addr);
        let token_type = type_info::type_of<TokenType>();
        
        if (!table::contains(&vault.token_reserves, token_type)) {
            return (
                @0x0,
                vector::empty<u8>(),
                vector::empty<u8>(),
                0,
                0,
                0,
                0  // Default curve type
            )
        };
        
        let reserve_info = table::borrow(&vault.token_reserves, token_type);
        (
            reserve_info.token_address,
            reserve_info.token_module_name,
            reserve_info.token_struct_name,
            reserve_info.reserve_x,
            reserve_info.reserve_y,
            reserve_info.last_update_time,
            reserve_info.curve_type
        )
    }

    // Get admin address
    #[view]
    public fun get_admin(): address acquires Vault {
        let resource_addr = get_resource_account_address();
        let vault = borrow_global<Vault>(resource_addr);
        vault.admin
    }

    // Get token count
    #[view]
    public fun get_token_count(): u64 acquires Vault {
        let resource_addr = get_resource_account_address();
        let vault = borrow_global<Vault>(resource_addr);
        vector::length(&vault.token_types)
    }

    // Modify is_initialized to use calculated resource account address
    fun is_initialized(): bool {
        let resource_addr = get_resource_account_address();
        exists<Vault>(resource_addr) && 
        exists<UserShares>(resource_addr) && 
        exists<VaultResource>(resource_addr)
    }

    // Update get_initialization_status to use calculated address
    #[view]
    public fun get_initialization_status(): (bool, bool, bool) {
        let resource_addr = get_resource_account_address();
        (
            exists<Vault>(resource_addr),
            exists<UserShares>(resource_addr),
            exists<VaultResource>(resource_addr)
        )
    }

    // Get the resource account address
    #[view]
    public fun get_resource_address(): address {
        get_resource_account_address()
    }

    // Get detailed initialization info including resource account address
    #[view]
    public fun get_initialization_info(): (address, bool, bool, bool) {
        let resource_addr = get_resource_account_address();
        (
            resource_addr,
            exists<Vault>(resource_addr),
            exists<UserShares>(resource_addr),
            exists<VaultResource>(resource_addr)
        )
    }

    // Get swap prerequisites
    #[view]
    public fun get_swap_prerequisites<TokenType>(
        admin_addr: address
    ): (bool, u64, bool) acquires Vault {
        let resource_addr = get_resource_account_address();
        let vault = borrow_global<Vault>(resource_addr);
        (
            vault.vault_enabled,
            coin::balance<AptosCoin>(admin_addr),
            admin_addr == vault.admin
        )
    }

    // Register new token type for vault
    public entry fun register_token<TokenType>(admin: &signer) acquires Vault, VaultResource {
        let resource_addr = get_resource_account_address();
        let vault = borrow_global_mut<Vault>(resource_addr);
        
        // 1. Check if vault is initialized
        assert!(is_initialized(), ENOT_INITIALIZED);
        
        // 2. Check admin
        assert!(signer::address_of(admin) == vault.admin, ENOT_ADMIN);
        
        // 3. Check if token is already registered
        assert!(!coin::is_account_registered<TokenType>(resource_addr), ETOKEN_ALREADY_EXISTS);
        
        // 4. Get resource signer with check
        assert!(exists<VaultResource>(resource_addr), ERESOURCE_SIGNER_ERROR);
        let resource_signer = get_resource_signer();
        
        // 5. Try to register token
        coin::register<TokenType>(&resource_signer);
        
        // 6. Verify registration was successful
        assert!(coin::is_account_registered<TokenType>(resource_addr), EREGISTER_FAILED);
    }

    // Check if token is registered
    #[view]
    public fun is_token_registered<TokenType>(): bool {
        let resource_addr = get_resource_account_address();
        coin::is_account_registered<TokenType>(resource_addr)
    }

    // Add a function to check registration prerequisites
    #[view]
    public fun check_register_prerequisites<TokenType>(
        admin_addr: address
    ): (bool, bool, bool, bool) acquires Vault {
        let resource_addr = get_resource_account_address();
        
        // Check if vault exists
        let vault_exists = exists<Vault>(resource_addr);
        if (!vault_exists) {
            return (false, false, false, false)
        };
        
        let vault = borrow_global<Vault>(resource_addr);
        (
            vault_exists,                                     // Vault exists
            vault.vault_enabled,                             // Vault is enabled
            admin_addr == vault.admin,                       // Is admin
            !coin::is_account_registered<TokenType>(resource_addr)  // Token not already registered
        )
    }

    #[view]
    public fun check_swap_detailed<TokenType>(
        admin_addr: address,
        amount: u64
    ): (bool, bool, bool, bool, bool, bool, u128, u128) acquires Vault {
        let resource_addr = get_resource_account_address();
        
        // Check if resource account exists
        let resource_exists = exists<Vault>(resource_addr);
        if (!resource_exists) {
            return (false, false, false, false, false, false, 0, 0)
        };
        
        let vault = borrow_global<Vault>(resource_addr);
        let (reserve_x, reserve_y) = router::get_reserves_size<AptosCoin, TokenType, Uncorrelated>();
        
        (
            resource_exists,                                  // Resource account exists
            vault.vault_enabled,                             // Vault is enabled
            admin_addr == vault.admin,                       // Is admin
            coin::value(&vault.coins) >= amount,             // Has enough APT
            coin::is_account_registered<TokenType>(resource_addr), // Token is registered
            reserve_x > 0 && reserve_y > 0,                  // Liquidity pool exists
            (reserve_x as u128),                            // APT in pool
            (reserve_y as u128)                             // Token in pool
        )
    }

    // Set token update time check
    public entry fun set_token_update_check<TokenType>(
        admin: &signer,
        check_enabled: bool
    ) acquires Vault {
        let admin_addr = signer::address_of(admin);
        let resource_addr = get_resource_account_address();
        let vault = borrow_global_mut<Vault>(resource_addr);
        assert!(admin_addr == vault.admin, ENOT_ADMIN);
        
        let token_type = type_info::type_of<TokenType>();
        assert!(table::contains(&vault.token_reserves, token_type), ETOKEN_NOT_FOUND);
        
        let reserve_info = table::borrow_mut(&mut vault.token_reserves, token_type);
        reserve_info.check_update_time = check_enabled;
    }

    // Set fee rate
    public entry fun set_fee(
        admin: &signer,
        new_fee: u64
    ) acquires Vault {
        let admin_addr = signer::address_of(admin);
        let resource_addr = get_resource_account_address();
        let vault = borrow_global_mut<Vault>(resource_addr);
        assert!(admin_addr == vault.admin, ENOT_ADMIN);
        assert!(new_fee <= 500, EINVALID_FEE); // Max 5%
        vault.fee = new_fee;
    }

    // Set fee wallet
    public entry fun set_fee_wallet(
        admin: &signer,
        new_wallet: address
    ) acquires Vault {
        let admin_addr = signer::address_of(admin);
        let resource_addr = get_resource_account_address();
        let vault = borrow_global_mut<Vault>(resource_addr);
        assert!(admin_addr == vault.admin, ENOT_ADMIN);
        assert!(new_wallet != @0x0, EINVALID_FEE_WALLET);
        vault.fee_wallet = new_wallet;
    }

    #[view]
    public fun get_withdrawal_info(
        user_addr: address
    ): (u128, u128, u128, u128) acquires Vault, UserShares {
        let resource_addr = get_resource_account_address();
        let vault = borrow_global<Vault>(resource_addr);
        let shares = &borrow_global<UserShares>(resource_addr).shares;
        
        if (!table::contains(shares, user_addr)) {
            return (0, 0, 0, 0)
        };
        
        let info = table::borrow(shares, user_addr);
        let total_apt = calculate_withdrawal_amount(info.amount, vault.total_shares, internal_get_vault_total_value(vault));
        let fee_amount = (total_apt * (vault.fee as u128)) / 10000;
        let user_amount = total_apt - fee_amount;  // Keep this to show user's portion
        
        (
            info.amount,           // User's shares
            total_apt,            // Total APT before fee
            user_amount,          // APT amount after fee (what user will receive)
            fee_amount            // Fee amount in APT (what fee_wallet will receive)
        )
    }
}

