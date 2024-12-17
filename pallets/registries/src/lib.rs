// This file is part of CORD – https://cord.network

// Copyright (C) Dhiway Networks Pvt. Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later

// CORD is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// CORD is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with CORD. If not, see <https://www.gnu.org/licenses/>.
//

//! # Registries Pallet
//!
//! The Registries pallet provides a framework for creating and managing
//! isolated registries within the CORD blockchain that can be governed and
//! moderated with a fine-grained permission system. It allows for the creation,
//! changing the status of the registry, as well as the management of delegates
//! within these registry.
//!
//! ## Overview
//!
//! The Registry pallet allows for the creation of distinct registry on the CORD
//! blockchain, each with its own set of rules and governance. These registry can
//! be used to manage different ecosystems or communities within the larger
//! blockchain environment. Registry are created with a unique identifier and can
//! be managed by appointed delegates.
//!
//! ## Interface
//!
//! The pallet provides dispatchable functions for registry management:
//!
//! - create: Initializes a new registry with a unique identifier.
//! - update: Updates the existing registry with newer data.
//! - revoke: Marks a registry as revoked, effectively changing it to revoked status.
//! - reinstate: Changes the status of the registry, returning it to active status.
//! - archive: Marks a registry as archived, effectively changing it to archived status.
//! - restore: Changes the status of the registry, returning it to non-archival status.
//! - add_delegate: Adds a delegate to a registry, granting them specific permissions.
//! - add_admin_delegate: Adds an admin delegate to a registry, granting them administrative
//!   permissions.
//! - add_audit_delegate: Adds an audit delegate to a registry, granting them audit permissions.
//! - remove_delegate: Removes a delegate from a registry, revoking their permissions.
//!
//!
//! ## Permissions
//!
//! The pallet uses a permissions system to manage the actions that delegates
//! can perform within a registry. Permissions are granular and can be assigned to
//! different roles, such as an admin or a regular delegate.
//!
//! ## Data Privacy
//!
//! The Registries pallet is designed with data privacy as a core consideration.
//! It does not directly store any personal or sensitive information on-chain.
//! Instead, it manages references to off-chain data, ensuring that the
//! blockchain layer remains compliant with data privacy regulations. Users and
//! developers are responsible for ensuring that the off-chain data handling
//! processes adhere to the applicable laws and standards.
//!
//! ## Usage
//!
//! The Registries pallet can be used by other pallets ex. Entries pallet to create
//! compartmentalized and governed sections of the blockchain. This is
//! particularly useful for applications that require distinct governance models
//! or privacy settings within a shared ecosystem.
//!
//! ## Governance Integration
//!
//! The Registries pallet is integrated with on-chain governance pallets to
//! allow registry administrators and delegates to propose changes, vote on
//! initiatives, or manage the registry in accordance with the collective decisions
//! of its members.
//!
//! ## Examples
//!
//! - Creating a new registry for a community-driven project.
//! - Archiving, Restoring a registry that is to be stashed for a while.
//! - Revoking, Re-instating a registry that is no longer active or has violated terms of use.
//! - Adding delegates to a registry to ensure ongoing compliance with governance standards.

// NOTE: This makes sure that this code is compiled WITHOUT std. This is done to ensure compatibility with wasmenvironment.
#![cfg_attr(not(feature = "std"), no_std)]
// NOTE: To ensure that clippy does not throw warnings when functions return unit type i.e ().
#![allow(clippy::unused_unit)]

// NOTE: conditionally compiles 'mock' if mock feature is enabled or while testing. Mock should not be compiled when used in production.
#[cfg(any(feature = "mock", test))]
pub mod mock;

// NOTE: conditionally compiles 'test' only when this code is being tested. Test should not be compiled when used in production.
#[cfg(test)]
mod tests;

// NOTE: ensure: a macro provided by substrate to perform assertions. eg: ensure!(1+1 == 2, "Math error");
// NOTE: StorageMap: a map of key-value pairs stored in the storage.
// NOTE: BoundedVec: a vector with a size constraint to ensure runtime safety.
use frame_support::{ensure, storage::types::StorageMap, BoundedVec};
// NOTE: brings types in scope.
pub mod types;
// NOTE: re-exports pallet and types.
pub use crate::{pallet::*, types::*};
// NOTE: Encode the data in a format suitable for storing or transmission between nodes.
use codec::Encode;
// NOTE: ??
use identifier::{
	types::{CallTypeOf, IdentifierTypeOf, Timepoint},
	EventEntryOf,
};
// NOTE: Hash: used to generate hash
// NOTE: UniqueSaturatedInto: a safe type conversion.
use sp_runtime::traits::{Hash, UniqueSaturatedInto};

/// Authorization Identifier
pub type AuthorizationIdOf = Ss58Identifier;
/// Type of the Registry Id
pub type RegistryIdOf = Ss58Identifier;
/// Tyoe of the Registry Digest
// NOTE: configures RegistryHashOf to whatever hashing algo the Config of the runtime has defined(eg. blake2_256, keccak_256)
pub type RegistryHashOf<T> = <T as frame_system::Config>::Hash;
/// Type of the Registry Creator
// NOTE: RegistryCreatorOf<T> is the format in which the public key or the addresses of the actors(like delegator, delegates) are stored. It is defined in the Config of the runtime. 
pub type RegistryCreatorOf<T> = <T as frame_system::Config>::AccountId;
/// Type of the Registry Template Id
pub type TemplateIdOf<T> = BoundedVec<u8, <T as Config>::MaxEncodedInputLength>;
/// Type of the Schema Id
// NOTE: Every schemas will have a different ID. It represents what schema the registry follows.
pub type SchemaIdOf = Ss58Identifier;
/// Type of Maximum allowed size of the Registry Blob
// NOTE: This is the maximum size of the blob of the registry. Declared in the Config of the runtime. 
pub type MaxRegistryBlobSizeOf<T> = <T as crate::Config>::MaxRegistryBlobSize;
/// Type of Registry Blob
// NOTE: It is a vector representiing the number of tx in each blob(every blob can have a max of MaxRegistryBlobSizeOf)
pub type RegistryBlobOf<T> = BoundedVec<u8, MaxRegistryBlobSizeOf<T>>;
/// Type of the Registry Authorization Details
// NOTE: when we delegate some permissions for a registry, we store it in this format. RegistryIdOf is the format of the 'registry_id' of the registry, RegistryCreatorOf<T> is the format of the 'delegate' and the 'delegator', Permissions is the format of the 'permissions'(i.e. ASSERT, DELEGATE, ADMIN).
pub type RegistryAuthorizationOf<T> =
	RegistryAuthorization<RegistryIdOf, RegistryCreatorOf<T>, Permissions>;
/// Type of Registry Details
// NOTE: RegistryDetailsOf<T> is the format of the details of the registry. The 'creator' of the registry is stored in the format of RegistryCreatorOf<T>, StatusOf represents whether it is 'revoked' or 'archived', RegistryHashOf<T> stores the unique 'digest'(representing the contents of the registry) of the registry and SchemaIdOf is the format of the 'schema_id' of the registry.
pub type RegistryDetailsOf<T> =
	RegistryDetails<RegistryCreatorOf<T>, StatusOf, RegistryHashOf<T>, SchemaIdOf>;

#[frame_support::pallet]
pub mod pallet {
	use super::*;
	pub use cord_primitives::{IsPermissioned, StatusOf};
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;
	pub use frame_system::WeightInfo;
	pub use identifier::{
		CordIdentifierType, IdentifierCreator, IdentifierTimeline, IdentifierType, Ss58Identifier,
	};

	/// The current storage version.
	// NOTE: Next if I wish to upgrade this pallet and roll out to my clients, I can increment this number.
	const STORAGE_VERSION: StorageVersion = StorageVersion::new(1);

	#[pallet::config]
	// NOTE: every pallet's Config trait must extend frame_system::Config
	pub trait Config: frame_system::Config + identifier::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		#[pallet::constant]
		// NOTE: maximum delegates allowed for a registry
		type MaxRegistryDelegates: Get<u32>;

		#[pallet::constant]
		// NOTE: maximum blob size for this registry
		type MaxRegistryBlobSize: Get<u32>;

		#[pallet::constant]
		// NOTE: maximum length of the input
		type MaxEncodedInputLength: Get<u32>;

		// Weight information for extrinsics in this pallet.
		// NOTE: Weight information for extrinsics in this pallet, like how much maximum resources it takes to process each extrinsic.
		type WeightInfo: WeightInfo;
	}

	// NOTE: this macro marks this struct as the main entry point of the pallet, sets up a foundational structure for pallet to interact with the runtime.
	#[pallet::pallet]
	// NOTE: defines and sets the storage version of this pallet. Essential for upgrades.
	#[pallet::storage_version(STORAGE_VERSION)]
	pub struct Pallet<T>(_);

	// NOTE: hooks are functions that are called at certain points in the runtime lifecycle. For example, there are hooks like 'on_initialize', 'on_finalize', 'on_idle', 'offchain_worker', 'on_runtime_upgrade', 'on_validate_transaction'. But for this pallet we have not defined any hooks yet. 
	#[pallet::hooks]
	impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {}

	/// Registry information stored on chain.
	/// It maps from an identifier to its details.
	// NOTE: mapping from registry ID to registry details. Like
	// 
	// mapping(uint256 registryId => RegistryDetails) public registryInfo;
	// 
	// where RegistryDetails is a struct which holds info including creator, revoked, archived, digest, schema_id.
	// OptionQuery makes sure that querying an uninitialized key returns None.
	#[pallet::storage]
	pub type RegistryInfo<T> =
		StorageMap<_, Blake2_128Concat, RegistryIdOf, RegistryDetailsOf<T>, OptionQuery>;

	/// Registry authorizations stored on-chain.
	/// It maps from an identifier to delegates.
	// NOTE: mapping from authorization ID to authorization details. Like
	// 
	// mapping(uint256 authorizationId => RegistryAuthorization) public authorizationInfo;
	// 
	// where RegistryAuthorization is a struct which holds info including registry_id, delegate, permissions, delegator.
	#[pallet::storage]
	pub type Authorizations<T> =
		StorageMap<_, Blake2_128Concat, AuthorizationIdOf, RegistryAuthorizationOf<T>, OptionQuery>;

	/// Registry delegates stored on chain.
	/// It maps from an identifier to a  bounded vec of delegates and
	/// permissions.
	// NOTE: This is a mapping from registry ID to the list of delegates. Like 
	//
	// mapping(uint256 registryId => address[] deleagateAddr) public registryIdToDelegateAddr;
	//
	// where length of delegateAddr can be a maximum of MaxRegistryDelegates
	// ValueQuery returns a default value(in this case an empty BoundedVec) if the key does not exist.
	#[pallet::storage]
	pub(super) type Delegates<T: Config> = StorageMap<
		_,
		Blake2_128Concat,
		RegistryIdOf,
		BoundedVec<RegistryCreatorOf<T>, T::MaxRegistryDelegates>,
		ValueQuery,
	>;

	// NOTE: marks this enum as the event enum for the pallet.
	#[pallet::event]
	// NOTE: generates a function 'deposit_event' to emit events. 'pub(super)' makes this function available only inside this module and the submodules.
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		/// A new registry authorization has been added.
		/// \[registry identifier, authorization,  delegate\]
		// NOTE: authorization will be an identifier that will prove the delegate's authority. 
		// 		 For eg: the identifier can be created using delegate address, registry id and permission 
		// 		 authorization = createSs58Identifier(delegateAddress, registryId, permission)w
		Authorization {
			registry_id: RegistryIdOf,
			authorization: AuthorizationIdOf,
			delegate: RegistryCreatorOf<T>,
		},
		/// A registry authorization has been removed.
		/// \[registry identifier, authorization, ]
		Deauthorization { registry_id: RegistryIdOf, authorization: AuthorizationIdOf },
		/// A new registry has been created.
		/// \[registry identifier, creator, authorization\]
		Create {
			registry_id: RegistryIdOf,
			creator: RegistryCreatorOf<T>,
			authorization: AuthorizationIdOf,
		},
		/// A registry has been revoked.
		/// \[registry identifier, authority\]
		Revoke { registry_id: RegistryIdOf, authority: RegistryCreatorOf<T> },
		/// A registry has been reinstated.
		/// \[registry identifier,  authority\]
		Reinstate { registry_id: RegistryIdOf, authority: RegistryCreatorOf<T> },
		/// A existing registry has been updated.
		/// \[registry identifier, updater, authorization\]
		Update {
			registry_id: RegistryIdOf,
			updater: RegistryCreatorOf<T>,
			authorization: AuthorizationIdOf,
		},
		/// A registry has been archived.
		/// \[registry identifier,  authority\]
		Archive { registry_id: RegistryIdOf, authority: RegistryCreatorOf<T> },
		/// A registry has been restored.
		/// \[registry identifier, authority\]
		Restore { registry_id: RegistryIdOf, authority: RegistryCreatorOf<T> },
	}

	#[pallet::error]
	#[derive(PartialEq)]
	pub enum Error<T> {
		/// Registry identifier is not unique
		RegistryAlreadyAnchored,
		/// Registry identifier not found
		RegistryNotFound,
		/// Only when the author is not the controller or delegate.
		UnauthorizedOperation,
		/// Invalid Identifier
		InvalidIdentifier,
		/// Invalid Identifier Length
		InvalidIdentifierLength,
		/// Registry delegation limit exceeded
		RegistryDelegatesLimitExceeded,
		/// Authority already added
		DelegateAlreadyAdded,
		/// Authorization Id not found
		AuthorizationNotFound,
		/// Delegate not found.
		DelegateNotFound,
		/// Registry not revoked.
		RegistryNotRevoked,
		// NOTE: how is 'RegistryAlreadyRevoked' different from 'RegistryRevoked'?
		/// Registry already revoked
		RegistryAlreadyRevoked,
		/// Registry revoked.
		RegistryRevoked,
		/// Registry not archived.
		RegistryNotArchived,
		// NOTE: how is 'RegistryAlreadyArchived' different from 'RegistryArchived'?
		/// Registry already arhived.
		RegistryAlreadyArchived,
		/// Registry not archived.
		RegistryArchived,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Adds a delegate with permission to assert new entries to a registry.
		///
		/// The ASSERT permission enables a delegate to add and sign new entries
		/// within the specified registry. This function is used to grant this
		/// permission to a delegate, provided that the caller has sufficient
		/// authorization, typically as an admin of the registry.
		///
		/// The function checks that the caller is authorized (as an admin) to add
		/// a delegate with ASSERT permissions to the registry. If the caller's
		/// authorization is verified, the delegate is added using the internal
		/// registry_delegate_addition function.
		///
		/// # Parameters
		/// - origin: The origin of the call, which must be signed by an admin of the registry.
		/// - registry_id: The unique identifier of the registry to which the delegate is being
		///   added.
		/// - delegate: The account identifier of the delegate being granted the ASSERT
		///   permission.
		/// - authorization: The authorization ID used to validate the caller's permission to add
		///   a delegate.
		///
		/// # Returns
		/// Returns Ok(()) if the delegate is successfully added with ASSERT
		/// permissions, or an Err if the operation fails due to authorization issues
		/// or internal errors during delegate addition.
		///
		/// # Errors
		/// - UnauthorizedOperation: If the caller does not have the necessary admin permissions
		///   for the registry.
		/// - Propagates errors from registry_delegate_addition if the addition fails.
		// NOTE: In substrate each dispatchable function is given an indexso that the runtime knows which function to execute when a transaction is submitted.
		#[pallet::call_index(0)]
		// NOTE: weight represents how much resources we wish to allocate for this function during the runtime. We have given it a weight of 0 presumably for testing, but in production it would be necessary to set a weight.
		#[pallet::weight({0})]
		pub fn add_delegate(
			// NOTE: 'origin' tells about the origin of the transaction(maybe like msg.sender). 'OriginFor' is a type that represents the origin of a transaction. 'OriginFor' is of the type 'RuntimeOrigin' which is declared in the Config for the runtime.
			origin: OriginFor<T>,
			registry_id: RegistryIdOf,
			delegate: RegistryCreatorOf<T>,
			authorization: AuthorizationIdOf,
		) -> DispatchResult {
			// NOTE: 'ensure_signed' uses match expression to make sure that the transaction is actually signed by an account and returns that accountId. If not, throws error.
			let creator = ensure_signed(origin)?;

			// NOTE: 'ensure_authorization_delegator_origin' checks that authorization is indeed associated with the caller, the registry is not revoked or archived, and the caller has DELEGATE or ADMIN permission.
			let auth_registry_id =
				Self::ensure_authorization_delegator_origin(&authorization, &creator)?;
			ensure!(auth_registry_id == registry_id, Error::<T>::UnauthorizedOperation);

			let permissions = Permissions::ASSERT;
			// NOTE: This function creates delegate authorization ID and ensures that this ID isn't a part of the 'Authorizations' mapping. If it is a unique identifier(which means that this delegate hasn't been added before), the delegate will be added to the 'Delegates' mapping and a new entry corresponding to this authorization ID will be added to the 'Authorizations' mapping. The global timeline is next updated and an event is emitted.
			Self::registry_delegate_addition(auth_registry_id, delegate, creator, permissions)?;

			Ok(())
		}

		/// Adds an administrative delegate to a registry.
		///
		/// This function grants the ADMIN permission to a specified delegate,
		/// allowing the delegate to manage other delegates and modify registry
		/// configurations. Only existing registry administrators can invoke this
		/// function to add another admin delegate.
		///
		/// The function ensures that the caller has sufficient administrative
		/// privileges in the registry and that the registry_id matches the
		/// authorization. If the checks pass, the delegate is added with ADMIN
		/// permissions using the internal registry_delegate_addition function.
		///
		/// # Parameters
		/// - origin: The origin of the call, which must be signed by an existing administrator of
		///   the registry.
		/// - registry_id: The unique identifier of the registry to which the admin delegate is
		///   being added.
		/// - delegate: The account identifier of the delegate being granted admin permissions.
		/// - authorization: The authorization ID used to validate the caller's permission to add
		///   an admin delegate to the specified registry.
		///
		/// # Returns
		/// Returns Ok(()) if the admin delegate is successfully added, or an Err
		/// if the operation fails, such as when the caller lacks the necessary
		/// permissions or if there's an internal error during delegate addition.
		///
		/// # Errors
		/// - UnauthorizedOperation: If the caller does not have admin permissions in the
		///   registry.
		/// - Propagates errors from registry_delegate_addition if delegate addition fails.
		#[pallet::call_index(1)]
		#[pallet::weight({0})]
		pub fn add_admin_delegate(
			origin: OriginFor<T>,
			registry_id: RegistryIdOf,
			delegate: RegistryCreatorOf<T>,
			authorization: AuthorizationIdOf,
		) -> DispatchResult {
			let creator = ensure_signed(origin)?;

			// NOTE: 'ensure_authorization_admin_origin' checks that authorization is indeed associated with the caller, the registry is not revoked or archived, and the caller has ADMIN permission.
			let auth_registry_id =
				Self::ensure_authorization_admin_origin(&authorization, &creator)?;

			// NOTE: ensure that the registry given as input is actually the one on which the caller is authorized to add an admin delegate.
			ensure!(auth_registry_id == registry_id, Error::<T>::UnauthorizedOperation);

			let permissions = Permissions::ADMIN;
			Self::registry_delegate_addition(auth_registry_id, delegate, creator, permissions)?;

			Ok(())
		}

		/// Adds an audit delegate to a registry.
		///
		/// The AUDIT permission allows the delegate to perform oversight and
		/// compliance checks within the registry. This function is used to grant
		/// these audit privileges to a delegate. It checks that the caller has the
		/// necessary administrative rights to add an audit delegate to the registry.
		///
		/// If the caller is authorized, the delegate is added with the AUDIT
		/// permission using the internal registry_delegate_addition function.
		///
		/// # Parameters
		/// - origin: The origin of the call, which must be signed by an existing administrator of
		///   the registry.
		/// - registry_id: The unique identifier of the registry to which the audit delegate is
		///   being added.
		/// - delegate: The account identifier of the delegate being granted audit permissions.
		/// - authorization: The authorization ID used to validate the caller's permission to add
		///   the audit delegate.
		///
		/// # Returns
		/// Returns Ok(()) if the audit delegate is successfully added, or an Err
		/// if the operation fails due to authorization issues or internal errors
		/// during delegate addition.
		///
		/// # Errors
		/// - UnauthorizedOperation: If the caller does not have the necessary admin permissions
		///   for the registry.
		/// - Propagates errors from registry_delegate_addition if delegate addition fails.
		#[pallet::call_index(2)]
		#[pallet::weight({0})]
		pub fn add_delegator(
			origin: OriginFor<T>,
			registry_id: RegistryIdOf,
			delegate: RegistryCreatorOf<T>,
			authorization: AuthorizationIdOf,
		) -> DispatchResult {
			let creator = ensure_signed(origin)?;

			let auth_registry_id =
				Self::ensure_authorization_admin_origin(&authorization, &creator)?;

			ensure!(auth_registry_id == registry_id, Error::<T>::UnauthorizedOperation);

			let permissions = Permissions::DELEGATE;
			Self::registry_delegate_addition(auth_registry_id, delegate, creator, permissions)?;

			Ok(())
		}

		/// Removes a delegate from a specified registry.
		///
		/// This function removes an existing delegate from a registry, identified
		/// by the registry_id and the delegate's remove_authorization ID.
		/// It ensures that the registry exists, is not archived or revoked, and that
		/// the provided authorization corresponds to a delegate in the registry.
		/// Additionally, it verifies that the caller has the authority (admin rights)
		/// to remove the delegate.
		///
		/// # Parameters
		/// - origin: The origin of the call, which must be signed by an admin of the registry.
		/// - registry_id: The unique identifier of the registry from which the delegate is being
		///   removed.
		/// - remove_authorization: The authorization ID of the delegate to be removed.
		/// - authorization: The authorization ID validating the caller’s permission to perform
		///   the removal.
		///
		/// # Returns
		/// - DispatchResult: Returns Ok(()) if the delegate was successfully removed, or an
		///   error (DispatchError) if any of the checks fail.
		///
		/// # Errors
		/// - AuthorizationNotFound: If the provided remove_authorization does not exist.
		/// - UnauthorizedOperation: If the origin is not authorized to remove a delegate from the
		///   registry.
		/// - RegistryNotFound: If the specified registry_id does not correspond to an existing
		///   registry.
		/// - RegistryArchived: If the registry is archived and no longer active.
		/// - RegistryRevoked: If the registry has been revoked.
		/// - DelegateNotFound: If the delegate specified by remove_authorization is not found
		///   in the registry.
		///
		/// # Events
		/// - Deauthorization: Emitted when a delegate is successfully removed from the registry.
		///   The event includes the registry ID and the authorization ID of the removed delegate.
		#[pallet::call_index(3)]
		#[pallet::weight({0})]
		pub fn remove_delegate(
			origin: OriginFor<T>,
			registry_id: RegistryIdOf,
			// NOTE: this is the authorization ID od the delegate to be removed
			remove_authorization: AuthorizationIdOf,
			// NOTE: this(like previous cases) is the authorization ID of the caller
			authorization: AuthorizationIdOf,
		) -> DispatchResult {
			let creator = ensure_signed(origin)?;
			// NOTE: ensures that the delegate corresponding to the authorization is indeed the creator, the registry is not revoked or archived and that the permission with this delegate is that of ADMIN.
			let auth_registry_id =
				Self::ensure_authorization_admin_remove_origin(&authorization, &creator)?;

			// Ensure remover does not de-delagate themselves &
			// remover has valid authoirzation for this particular registry-id.
			ensure!(authorization != remove_authorization, Error::<T>::UnauthorizedOperation);
			ensure!(auth_registry_id == registry_id, Error::<T>::UnauthorizedOperation);

			// Ensure the authorization exists and retrieve its details.
			let authorization_details = Authorizations::<T>::get(&remove_authorization)
				.ok_or(Error::<T>::AuthorizationNotFound)?;

			let mut delegates = Delegates::<T>::get(&registry_id);
			if let Some(index) = delegates.iter().position(|d| d == &authorization_details.delegate)
			{
				// NOTE: should we try and use 'swap_remove' to better our performance? Can be done only if the order of the 'delegates' vector is not important.
				delegates.remove(index);
				Delegates::<T>::insert(&registry_id, delegates);

				Authorizations::<T>::remove(&remove_authorization);

				Self::update_activity(
					&registry_id,
					IdentifierTypeOf::RegistryAuthorization,
					CallTypeOf::Deauthorization,
				)?;

				Self::deposit_event(Event::Deauthorization {
					registry_id,
					authorization: remove_authorization,
				});

				Ok(())
			} else {
				Err(Error::<T>::DelegateNotFound.into())
			}
		}

		/// Creates a new registry with a unique identifier based on the provided
		/// registry digest and the creator's identity.
		///
		/// This function generates a unique identifier for the registry by hashing
		/// the encoded digest of the registry and the creator's identifier. It ensures that the
		/// generated registry identifier is not already in use. An authorization
		/// ID is also created for the new registry, which is used to manage
		/// delegations. The creator is automatically added as a delegate with
		/// full permissions.
		///
		/// # Parameters
		/// - origin: The origin of the transaction, signed by the creator.
		/// - registry_id: A unique code created to identify the registry.
		/// - digest: The digest representing the registry data to be created.
		/// - schema_id: (Optional) A unique code represnting the Schema.
		/// - blob: (Optional) Metadata or data associated with the registry.
		///
		/// # Returns
		/// - DispatchResult: Returns Ok(()) if the registry is successfully created, or an
		///   error (DispatchError) if:
		///   - The generated registry identifier is already in use.
		///   - The generated authorization ID has an invalid length.
		///   - The registry exceeds the allowed delegate limit.
		///
		/// # Errors
		/// - InvalidIdentifierLength: If the generated identifiers for the registry or
		///   authorization have invalid lengths.
		/// - RegistryAlreadyAnchored: If the registry identifier already exists.
		/// - RegistryDelegatesLimitExceeded: If the registry exceeds the maximum number of
		///   allowed delegates.
		///
		/// # Events
		/// - Create: Emitted when a new registry is successfully created. It includes the
		///   registry identifier, the creator's identifier, and the authorization ID.
		#[pallet::call_index(4)]
		#[pallet::weight({0})]
		pub fn create(
			origin: OriginFor<T>,
			_registry_id: RegistryIdOf,
			digest: RegistryHashOf<T>,
			schema_id: Option<SchemaIdOf>,
			// NOTE: blob is not something that is actually used in the function but is still included in the parameters. The reason being that the digest is included in the blob and if we ever want to query back, we can look for 'create' transacations and see which blob this transaction was included in. 
			_blob: Option<RegistryBlobOf<T>>,
		) -> DispatchResult {
			let creator = ensure_signed(origin)?;

			// TODO: Create the identifier at SDK level & validate at chain level.
			// Id Digest = concat (H(<scale_encoded_registry_input_digest>,
			// <scale_encoded_creator_identifier>))
			// NOTE: Using the hashing function declared in the Config, which is defined in the runtime, we try to create an id digest(which will be used to create the registry identifier), which is a hash of 'digest'(which is the digest of the data in the registry) with the creator account ID.
			let id_digest = <T as frame_system::Config>::Hashing::hash(
				&[&digest.encode()[..], &creator.encode()[..]].concat()[..],
			);

			// /* Ensure that registry_id is of valid ss58 format,
			//  * and also the type matches to be of Registries.
			//  */
			// ensure!(
			// 	Self::is_valid_ss58_format(&registry_id),
			// 	Error::<T>::InvalidRegistryIdentifier
			// );

			// NOTE: using the id_digest we create an identifier for the registry.
			let identifier = Ss58Identifier::create_identifier(
				&id_digest.encode()[..],
				IdentifierType::Registries,
			)
			.map_err(|_| Error::<T>::InvalidIdentifierLength)?;

			// NOTE: We need to them make sure that this identifier is not already in the mapping(which would mean that we are adding a registry with the same content and by the same creator twice).
			ensure!(
				!<RegistryInfo<T>>::contains_key(&identifier),
				Error::<T>::RegistryAlreadyAnchored
			);

			// Construct the authorization_id from the provided parameters.
			// Id Digest = concat (H(<scale_encoded_registry_identifier>,
			// <scale_encoded_creator_identifier> ))
			// NOTE: why is creator added twice here?
			let auth_id_digest = T::Hashing::hash(
				&[&identifier.encode()[..], &creator.encode()[..], &creator.encode()[..]].concat()
					[..],
			);

			// NOTE: using that digest and another identifier we create the authorization ID. 
			let authorization_id = Ss58Identifier::create_identifier(
				&auth_id_digest.encode(),
				IdentifierType::RegistryAuthorization,
			)
			.map_err(|_| Error::<T>::InvalidIdentifierLength)?;

			// NOTE: we create an empty bounded vector to store the delegates and add the creator as the first delegate.
			let mut delegates: BoundedVec<RegistryCreatorOf<T>, T::MaxRegistryDelegates> =
				BoundedVec::default();
			delegates
				.try_push(creator.clone())
				.map_err(|_| Error::<T>::RegistryDelegatesLimitExceeded)?;

			Delegates::<T>::insert(&identifier, delegates);

			// NOTE: whenever a new registry is created, the creator is added as a delegate with all the permissions. The delegator is also creator himself.
			Authorizations::<T>::insert(
				&authorization_id,
				RegistryAuthorizationOf::<T> {
					registry_id: identifier.clone(),
					delegate: creator.clone(),
					permissions: Permissions::all(),
					delegator: creator.clone(),
				},
			);

			<RegistryInfo<T>>::insert(
				&identifier,
				RegistryDetailsOf::<T> {
					creator: creator.clone(),
					revoked: false,
					archived: false,
					digest,
					schema_id,
				},
			);

			Self::update_activity(&identifier, IdentifierTypeOf::Registries, CallTypeOf::Genesis)
				.map_err(Error::<T>::from)?;

			Self::deposit_event(Event::Create {
				registry_id: identifier,
				creator,
				authorization: authorization_id,
			});

			Ok(())
		}

		/// Revokes a registry, marking it as no longer active.
		///
		/// This function marks a registry as revoked based on the provided registry
		/// ID. It checks that the registry exists, is not already revoked, and
		/// ensures that the caller has the authority to revoke the registry, as
		/// indicated by the provided authorization ID.
		///
		/// # Parameters
		/// - origin: The origin of the transaction, which must be signed by the creator or an
		///   admin with the appropriate authority.
		/// - registry_id: The identifier of the registry to be revoked.
		/// - authorization: An identifier for the authorization being used to validate the
		///   revocation.
		///
		/// # Returns
		/// - DispatchResult: Returns Ok(()) if the registry is successfully revoked, or an
		///   error (DispatchError) if:
		///   - The registry does not exist.
		///   - The registry is already revoked.
		///   - The caller does not have the authority to revoke the registry.
		///
		/// # Errors
		/// - RegistryNotFound: If the specified registry ID does not correspond to an existing
		///   registry.
		/// - RegistryAlreadyRevoked: If the registry has already been revoked.
		/// - UnauthorizedOperation: If the caller is not authorized to revoke the registry.
		///
		/// # Events
		/// - Revoke: Emitted when a registry is successfully revoked. It includes the registry ID
		///   and the authority who performed the revocation.
		#[pallet::call_index(6)]
		#[pallet::weight({0})]
		pub fn revoke(
			origin: OriginFor<T>,
			registry_id: RegistryIdOf,
			authorization: AuthorizationIdOf,
		) -> DispatchResult {
			let creator = ensure_signed(origin)?;

			// NOTE: 'ensure_authorization_admin_origin' checks that authorization is indeed associated with the caller, the registry is NOT revoked or archived, and the caller has ADMIN permission.
			let auth_registry_id =
				Self::ensure_authorization_admin_origin(&authorization, &creator)?;

			ensure!(auth_registry_id == registry_id, Error::<T>::UnauthorizedOperation);

			let registry_details =
				RegistryInfo::<T>::get(&registry_id).ok_or(Error::<T>::RegistryNotFound)?;

			ensure!(!registry_details.revoked, Error::<T>::RegistryAlreadyRevoked);

			<RegistryInfo<T>>::insert(
				&registry_id,
				RegistryDetailsOf::<T> { revoked: true, ..registry_details },
			);

			Self::update_activity(&registry_id, IdentifierTypeOf::Registries, CallTypeOf::Revoke)
				.map_err(Error::<T>::from)?;

			Self::deposit_event(Event::Revoke { registry_id, authority: creator });

			Ok(())
		}

		/// Reinstates a revoked registry, making it active again.
		///
		/// This function changes the status of a previously revoked registry to active
		/// based on the provided registry ID. It checks that the registry exists, is
		/// currently revoked, and ensures that the caller has the authority to reinstate
		/// the registry as indicated by the provided authorization ID.
		///
		/// # Parameters
		/// - origin: The origin of the transaction, which must be signed by the creator or an
		///   admin with the appropriate authority.
		/// - registry_id: The identifier of the registry to be reinstated.
		/// - authorization: An identifier for the authorization being used to validate the
		///   reinstatement.
		///
		/// # Returns
		/// - DispatchResult: Returns Ok(()) if the registry is successfully reinstated, or an
		///   error (DispatchError) if:
		///   - The registry does not exist.
		///   - The registry is not revoked.
		///   - The caller does not have the authority to reinstate the registry.
		///
		/// # Errors
		/// - RegistryNotFound: If the specified registry ID does not correspond to an existing
		///   registry.
		/// - RegistryNotRevoked: If the registry is not currently revoked.
		/// - UnauthorizedOperation: If the caller is not authorized to reinstate the registry.
		///
		/// # Events
		/// - Reinstate: Emitted when a registry is successfully reinstated. It includes the
		///   registry ID and the authority who performed the reinstatement.
		#[pallet::call_index(7)]
		#[pallet::weight({0})]
		pub fn reinstate(
			origin: OriginFor<T>,
			registry_id: RegistryIdOf,
			authorization: AuthorizationIdOf,
		) -> DispatchResult {
			let creator = ensure_signed(origin)?;

			// NOTE: ensure it is the correct delegate, the registry is INDEED revoked and creator has ADMIN permission.
			let auth_registry_id =
				Self::ensure_authorization_reinstate_origin(&authorization, &creator)?;

			ensure!(auth_registry_id == registry_id, Error::<T>::UnauthorizedOperation);

			let registry_details =
				RegistryInfo::<T>::get(&registry_id).ok_or(Error::<T>::RegistryNotFound)?;

			// NOTE: are we checking this twice? Once in ensure_authorization_reinstate_origin and once here?
			ensure!(registry_details.revoked, Error::<T>::RegistryNotRevoked);

			<RegistryInfo<T>>::insert(
				&registry_id,
				RegistryDetailsOf::<T> { revoked: false, ..registry_details },
			);

			Self::update_activity(
				&registry_id,
				IdentifierTypeOf::Registries,
				CallTypeOf::Reinstate,
			)
			.map_err(Error::<T>::from)?;

			Self::deposit_event(Event::Reinstate { registry_id, authority: creator });

			Ok(())
		}

		/// Updates the digest and optional blob of a registry.
		///
		/// This function allows the creator or an admin with the appropriate authority
		/// to update the digest and optionally the blob of an existing registry. It checks
		/// that the registry exists, ensures that the caller has the necessary authorization,
		/// and updates the registry with the new digest and blob (if provided).
		///
		/// # Parameters
		/// - origin: The origin of the transaction, which must be signed by the creator or an
		///   admin with the appropriate authority.
		/// - registry_id: The identifier of the registry to be updated.
		/// - digest: The new digest (hash) to be assigned to the registry.
		/// - blob: An optional new blob (data) to be assigned to the registry. If None, the
		///   existing blob remains unchanged.
		/// - authorization: An identifier for the authorization being used to validate the
		///   update.
		///
		/// # Returns
		/// - DispatchResult: Returns Ok(()) if the registry is successfully updated, or an
		///   error (DispatchError) if:
		///   - The registry does not exist.
		///   - The caller does not have the authority to update the registry.
		///
		/// # Errors
		/// - RegistryNotFound: If the specified registry ID does not correspond to an existing
		///   registry.
		/// - UnauthorizedOperation: If the caller is not authorized to update the registry.
		///
		/// # Events
		/// - Update: Emitted when a registry is successfully updated. It includes the registry
		///   ID, the updater, and the authorization used.
		#[pallet::call_index(8)]
		#[pallet::weight({0})]
		pub fn update(
			origin: OriginFor<T>,
			registry_id: RegistryIdOf,
			digest: RegistryHashOf<T>,
			_blob: Option<RegistryBlobOf<T>>,
			authorization: AuthorizationIdOf,
		) -> DispatchResult {
			let creator = ensure_signed(origin)?;

			let mut registry =
				RegistryInfo::<T>::get(&registry_id).ok_or(Error::<T>::RegistryNotFound)?;

			// NOTE: ensures correct delegate, has ADMIN permission, and registry is not archived or revoked
			let auth_registry_id =
				Self::ensure_authorization_admin_origin(&authorization, &creator)?;
			ensure!(auth_registry_id == registry_id, Error::<T>::UnauthorizedOperation);

			registry.digest = digest;

			<RegistryInfo<T>>::insert(&registry_id, registry);

			Self::update_activity(&registry_id, IdentifierTypeOf::Registries, CallTypeOf::Update)
				.map_err(Error::<T>::from)?;

			Self::deposit_event(Event::Update {
				registry_id: registry_id.clone(),
				updater: creator,
				authorization,
			});

			Ok(())
		}

		/// Archives a registry, marking it as inactive.
		///
		/// This function allows the creator or an admin with the appropriate authority
		/// to archive an existing registry. It checks that the registry exists, is not already
		/// archived, and ensures that the caller has the necessary authorization to perform the
		/// archival.
		///
		/// # Parameters
		/// - origin: The origin of the transaction, which must be signed by the creator or an
		///   admin with the appropriate authority.
		/// - registry_id: The identifier of the registry to be archived.
		/// - authorization: An identifier for the authorization being used to validate the
		///   archival.
		///
		/// # Returns
		/// - DispatchResult: Returns Ok(()) if the registry is successfully archived, or an
		///   error (DispatchError) if:
		///   - The registry does not exist.
		///   - The registry is already archived.
		///   - The caller does not have the authority to archive the registry.
		///
		/// # Errors
		/// - RegistryNotFound: If the specified registry ID does not correspond to an existing
		///   registry.
		/// - RegistryAlreadyArchived: If the registry is already archived.
		/// - UnauthorizedOperation: If the caller is not authorized to archive the registry.
		///
		/// # Events
		/// - Archive: Emitted when a registry is successfully archived. It includes the registry
		///   ID and the authority who performed the archival.
		#[pallet::call_index(9)]
		#[pallet::weight({0})]
		pub fn archive(
			origin: OriginFor<T>,
			registry_id: RegistryIdOf,
			authorization: AuthorizationIdOf,
		) -> DispatchResult {
			let creator = ensure_signed(origin)?;

			let auth_registry_id =
				Self::ensure_authorization_admin_origin(&authorization, &creator)?;

			ensure!(auth_registry_id == registry_id, Error::<T>::UnauthorizedOperation);

			let registry_details =
				RegistryInfo::<T>::get(&registry_id).ok_or(Error::<T>::RegistryNotFound)?;

			ensure!(!registry_details.archived, Error::<T>::RegistryAlreadyArchived);

			<RegistryInfo<T>>::insert(
				&registry_id,
				RegistryDetailsOf::<T> { archived: true, ..registry_details },
			);

			Self::update_activity(&registry_id, IdentifierTypeOf::Registries, CallTypeOf::Archive)
				.map_err(Error::<T>::from)?;

			Self::deposit_event(Event::Archive { registry_id, authority: creator });

			Ok(())
		}

		/// Restores an archived registry, making it active again.
		///
		/// This function allows the creator or an admin with the appropriate authority
		/// to restore an archived registry. It checks that the registry exists, is currently
		/// archived, and ensures that the caller has the necessary authorization to perform the
		/// restoration.
		///
		/// # Parameters
		/// - origin: The origin of the transaction, which must be signed by the creator or an
		///   admin with the appropriate authority.
		/// - registry_id: The identifier of the registry to be restored.
		/// - authorization: An identifier for the authorization being used to validate the
		///   restoration.
		///
		/// # Returns
		/// - DispatchResult: Returns Ok(()) if the registry is successfully restored, or an
		///   error (DispatchError) if:
		///   - The registry does not exist.
		///   - The registry is not archived.
		///   - The caller does not have the authority to restore the registry.
		///
		/// # Errors
		/// - RegistryNotFound: If the specified registry ID does not correspond to an existing
		///   registry.
		/// - RegistryNotArchived: If the registry is not currently archived.
		/// - UnauthorizedOperation: If the caller is not authorized to restore the registry.
		///
		/// # Events
		/// - Restore: Emitted when a registry is successfully restored. It includes the registry
		///   ID and the authority who performed the restoration.
		#[pallet::call_index(10)]
		#[pallet::weight({0})]
		pub fn restore(
			origin: OriginFor<T>,
			registry_id: RegistryIdOf,
			authorization: AuthorizationIdOf,
		) -> DispatchResult {
			let creator = ensure_signed(origin)?;

			// NOTE: ensure correct delegate, has ADMIN permission and registry is archived.
			let auth_registry_id =
				Self::ensure_authorization_restore_origin(&authorization, &creator)?;

			ensure!(auth_registry_id == registry_id, Error::<T>::UnauthorizedOperation);

			let registry_details =
				RegistryInfo::<T>::get(&registry_id).ok_or(Error::<T>::RegistryNotFound)?;

			// NOTE: are we checking archived status of the registry twice? 
			ensure!(registry_details.archived, Error::<T>::RegistryNotArchived);

			<RegistryInfo<T>>::insert(
				&registry_id,
				RegistryDetailsOf::<T> { archived: false, ..registry_details },
			);

			Self::update_activity(&registry_id, IdentifierTypeOf::Registries, CallTypeOf::Restore)
				.map_err(Error::<T>::from)?;

			Self::deposit_event(Event::Restore { registry_id, authority: creator });

			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	/// Adds a delegate to a registry with specified permissions.
	///
	/// This function will add a new delegate to a registry, given the registry's ID,
	/// the delegate's information, and the required permissions. It constructs
	/// an authorization ID based on the registry ID, delegate, and creator,
	/// ensuring that the delegate is not already added. It also checks that the
	/// registry is not archived and is not revoked.
	fn registry_delegate_addition(
		registry_id: RegistryIdOf,
		delegate: RegistryCreatorOf<T>,
		creator: RegistryCreatorOf<T>,
		permissions: Permissions,
	) -> Result<(), Error<T>> {
		// Id Digest = concat (H(<scale_encoded_registry_identifier>,
		// <scale_encoded_creator_identifier>, <scale_encoded_delegate_identifier>))
		// NOTE: we first create the authorization identifier for the new delegate by hashing 'registry_id', 'delegate' and 'creator'
		let id_digest = T::Hashing::hash(
			&[&registry_id.encode()[..], &delegate.encode()[..], &creator.encode()[..]].concat()[..],
		);

		// NOTE: then we create the delegate authorization identifier(which needs to be in SS58 format) by using the hash and identifier type as input. 'map_err' converts a Result<T, E> to Result<T, F>. It might be that every error wihc create_identifier might throw would be converted to 'InvalidIdentifierLength'.
		let delegate_authorization_id = Ss58Identifier::create_identifier(
			&id_digest.encode(),
			IdentifierType::RegistryAuthorization,
		)
		.map_err(|_| Error::<T>::InvalidIdentifierLength)?;

		// NOTE: the authorization Id dhould not already be a part of the 'authorizations' mapping. 
		ensure!(
			!Authorizations::<T>::contains_key(&delegate_authorization_id),
			Error::<T>::DelegateAlreadyAdded
		);

		// NOTE: get the list of the delegates for that registry
		let mut delegates = Delegates::<T>::get(&registry_id);
		// NOTE: try pushing the new delegate accountin the delegates list, if it exceeds the upper bound, it will throw an error.
		delegates
			.try_push(delegate.clone())
			.map_err(|_| Error::<T>::RegistryDelegatesLimitExceeded)?;
		// NOTE: I questioned the need for inserting the updates 'delegates' into the 'delegates' mapping, could not understand why updating it would not reflect changes in the mapping itself. It is because methods like Delegates::get(...) gives us back a local copy of the delegates list and not the actual list stored in the mapping. Hence post updation, we need to insert the updated list into the mapping.
		Delegates::<T>::insert(&registry_id, delegates);
		
		// NOTE: add the new delegate to the 'authorizations' mapping
		Authorizations::<T>::insert(
			&delegate_authorization_id,
			RegistryAuthorizationOf::<T> {
				registry_id: registry_id.clone(),
				delegate: delegate.clone(),
				permissions,
				delegator: creator,
			},
		);

		// NOTE: updates the global timeline with a new activity of delegate been added to a registry.
		Self::update_activity(
			&registry_id,
			IdentifierTypeOf::RegistryAuthorization,
			CallTypeOf::Authorization,
		)
		.map_err(Error::<T>::from)?;

		// NOTE: 'deposit_event' is the function that will be called to emit an event.
		Self::deposit_event(Event::Authorization {
			registry_id,
			authorization: delegate_authorization_id,
			delegate,
		});

		Ok(())
	}

	/// Checks if a given entity is a delegate for the specified registry.
	///
	/// This function retrieves the list of delegates for a registry and determines
	/// whether the specified delegate is among them. It is a read-only
	/// operation and does not modify the state.
	pub fn is_a_delegate(tx_id: &RegistryIdOf, delegate: RegistryCreatorOf<T>) -> bool {
		<Delegates<T>>::get(tx_id).iter().any(|d| d == &delegate)
	}

	/// Verifies if a given delegate has a specific authorization.
	///
	/// This function checks if the provided delegate is associated with the
	/// given authorization ID and has the 'ASSERT' permission.
	pub fn ensure_authorization_origin(
		authorization_id: &AuthorizationIdOf,
		delegate: &RegistryCreatorOf<T>,
	) -> Result<RegistryIdOf, Error<T>> {
		let d =
			<Authorizations<T>>::get(authorization_id).ok_or(Error::<T>::AuthorizationNotFound)?;

		ensure!(d.delegate == *delegate, Error::<T>::UnauthorizedOperation);

		Self::validate_registry_for_transaction(&d.registry_id)?;

		ensure!(d.permissions.contains(Permissions::ASSERT), Error::<T>::UnauthorizedOperation);

		Ok(d.registry_id)
	}

	/// Verifies if a given delegate has a specific authorization.
	///
	/// This function checks if the provided delegate is associated with the
	/// given authorization ID and has the 'ADMIN' permission.
	/// This asserts for delegates authorization has the permission to reinstate.
	pub fn ensure_authorization_reinstate_origin(
		authorization_id: &AuthorizationIdOf,
		delegate: &RegistryCreatorOf<T>,
	) -> Result<RegistryIdOf, Error<T>> {
		let d =
			<Authorizations<T>>::get(authorization_id).ok_or(Error::<T>::AuthorizationNotFound)?;

		ensure!(d.delegate == *delegate, Error::<T>::UnauthorizedOperation);

		// NOTE: ensures that the registry is revoked.
		Self::validate_registry_for_reinstate_transaction(&d.registry_id)?;

		ensure!(d.permissions.contains(Permissions::ADMIN), Error::<T>::UnauthorizedOperation);
		// ensure!(d.permissions.contains(Permissions::ASSERT), Error::<T>::UnauthorizedOperation);

		Ok(d.registry_id)
	}

	/// Verifies if a given delegate has a specific authorization.
	///
	/// This function checks if the provided delegate is associated with the
	/// given authorization ID and has the 'ADMIN' permission.
	/// This asserts for delegates authorization has the permission to restore.
	pub fn ensure_authorization_restore_origin(
		authorization_id: &AuthorizationIdOf,
		delegate: &RegistryCreatorOf<T>,
	) -> Result<RegistryIdOf, Error<T>> {
		let d =
			<Authorizations<T>>::get(authorization_id).ok_or(Error::<T>::AuthorizationNotFound)?;

		ensure!(d.delegate == *delegate, Error::<T>::UnauthorizedOperation);

		// NOTE: ensure registry is INDEED archived.
		Self::validate_registry_for_restore_transaction(&d.registry_id)?;

		ensure!(d.permissions.contains(Permissions::ADMIN), Error::<T>::UnauthorizedOperation);

		Ok(d.registry_id)
	}

	/// Checks if a given delegate is an admin for the registry associated with the
	/// authorization ID.
	///
	/// This function verifies whether the specified delegate is the admin of
	/// the registry by checking the 'ADMIN' permission within the authorization
	/// tied to the provided authorization ID.
	pub fn ensure_authorization_admin_origin(
		authorization_id: &AuthorizationIdOf,
		delegate: &RegistryCreatorOf<T>,
	) -> Result<RegistryIdOf, Error<T>> {
		let d =
			<Authorizations<T>>::get(authorization_id).ok_or(Error::<T>::AuthorizationNotFound)?;

		// NOTE: need to check three things, first if the authorization ID corresponds to this delegate and second, if the registry is archived or revoked and third, if the permission with this delegate is that of ADMIN.
		ensure!(d.delegate == *delegate, Error::<T>::UnauthorizedOperation);

		// NOTE: ensures that the registry we wish to work on isn't archived or revoked.
		Self::validate_registry_for_transaction(&d.registry_id)?;

		ensure!(d.permissions.contains(Permissions::ADMIN), Error::<T>::UnauthorizedOperation);

		Ok(d.registry_id)
	}

	/// Ensures that the given delegate is authorized to perform an audit
	/// operation on a registry.
	///
	/// This function checks whether the provided authorization_id corresponds
	/// to an existing authorization and whether the delegate associated with
	/// that authorization is allowed to perform audit operations. It also
	/// increments usage and validates the registry for transactions.
	// NOTE: this function is used to check whether the delegate is authorised to perform certain operations using the authorizationId. 
	pub fn ensure_authorization_delegator_origin(
		authorization_id: &AuthorizationIdOf,
		delegate: &RegistryCreatorOf<T>,
	) -> Result<RegistryIdOf, Error<T>> {
		// NOTE: we go into the 'Authorizations' map and retrieve the struct associated to 'authorization_id'. 
		let d =
			<Authorizations<T>>::get(authorization_id).ok_or(Error::<T>::AuthorizationNotFound)?;

		// NOTE: ensures that the delegate associated with the authorization is the same as the provided delegate.
		ensure!(d.delegate == *delegate, Error::<T>::UnauthorizedOperation);

		// NOTE: this line ensures that the registry we wish to work on isn't archived or revoked. 
		Self::validate_registry_for_transaction(&d.registry_id)?;

		// NOTE: only the delegate with 'DELEGATE' and 'ADMIN' permissions can add delegates. This line ensures that.
		ensure!(
			d.permissions.contains(Permissions::DELEGATE | Permissions::ADMIN),
			Error::<T>::UnauthorizedOperation
		);

		Ok(d.registry_id)
	}

	/// Checks if a given delegate is an admin for the registry associated with the
	/// authorization ID.
	///
	/// This function verifies whether the specified delegate is the admin of
	/// the registry by checking the 'ADMIN' permission within the authorization
	/// tied to the provided authorization ID.
	pub fn ensure_authorization_admin_remove_origin(
		authorization_id: &AuthorizationIdOf,
		delegate: &RegistryCreatorOf<T>,
	) -> Result<RegistryIdOf, Error<T>> {
		let d =
			<Authorizations<T>>::get(authorization_id).ok_or(Error::<T>::AuthorizationNotFound)?;

		ensure!(d.delegate == *delegate, Error::<T>::UnauthorizedOperation);

		Self::validate_registry_for_transaction(&d.registry_id)?;

		ensure!(d.permissions.contains(Permissions::ADMIN), Error::<T>::UnauthorizedOperation);

		Ok(d.registry_id)
	}

	/// Validates that a registry is eligible for a new transaction.
	///
	/// This function ensures that a registry is not archived, is not revoked.
	/// It is a critical check that enforces the integrity and
	/// constraints of registry usage on the chain.
	pub fn validate_registry_for_transaction(registry_id: &RegistryIdOf) -> Result<(), Error<T>> {
		let registry_details =
			RegistryInfo::<T>::get(registry_id).ok_or(Error::<T>::RegistryNotFound)?;

		// Ensure the Registry is not archived.
		if registry_details.archived {
			return Err(Error::<T>::RegistryArchived);
		}

		// Ensure the Registry is not revoked.
		if registry_details.revoked {
			return Err(Error::<T>::RegistryRevoked);
		}

		Ok(())
	}

	/// Validates a registry for restore transactions.
	///
	/// This function checks that the specified registry exists.
	/// It is designed to be called before,
	/// performing any administrative actions on a registry to ensure
	/// that the registry is in a proper state for such transactions.
	pub fn validate_registry_for_restore_transaction(
		registry_id: &RegistryIdOf,
	) -> Result<(), Error<T>> {
		let registry_details =
			RegistryInfo::<T>::get(registry_id).ok_or(Error::<T>::RegistryNotFound)?;

		// Ensure the Registry is archived.
		if !registry_details.archived {
			return Err(Error::<T>::RegistryNotArchived);
		}

		Ok(())
	}

	/// Validates a registry for reinstate transactions.
	///
	/// This function checks that the specified registry exists.
	/// It is designed to be called before performing any administrative
	/// actions on a registry to ensure either the registry is in a proper state for such
	/// transactions.
	pub fn validate_registry_for_reinstate_transaction(
		registry_id: &RegistryIdOf,
	) -> Result<(), Error<T>> {
		let registry_details =
			RegistryInfo::<T>::get(registry_id).ok_or(Error::<T>::RegistryNotFound)?;

		// Ensure the Registry is revoked.
		if !registry_details.revoked {
			return Err(Error::<T>::RegistryNotRevoked);
		}

		Ok(())
	}

	/// Checks if the given authorization ID is associated with an ADMIN permission for the
	/// provided delegate.
	///
	/// This function retrieves the authorization entry from storage and verifies whether the
	/// delegate matches the associated RegistryCreator and if the delegate holds the ADMIN
	/// permission.
	///
	/// # Parameters
	/// - authorization_id: The identifier of the authorization to check.
	/// - delegate: The delegate (typically the creator of the registry) to check the
	///   authorization for.
	///
	/// # Returns
	/// - true if the authorization exists, the delegate matches the stored delegate, and the
	///   delegate has the ADMIN permission.
	/// - false if the authorization does not exist, the delegate does not match, or the
	///   delegate lacks the ADMIN permission.
	///
	/// # Example
	/// 
	/// let is_admin = is_admin_authorization(&authorization_id, &delegate);
	/// if is_admin {
	///     // The delegate has admin permissions
	/// } else {
	///     // The delegate does not have admin permissions
	/// }
	/// 
	pub fn is_admin_authorization(
		authorization_id: &AuthorizationIdOf,
		delegate: &RegistryCreatorOf<T>,
	) -> bool {
		if let Some(auth) = <Authorizations<T>>::get(authorization_id) {
			if auth.delegate == *delegate && auth.permissions.contains(Permissions::ADMIN) {
				return true;
			}
		}
		false
	}

	/// Updates the global timeline with a new activity event for a registry.
	///
	/// This function is an internal mechanism that logs each significant change
	/// to a registry on the global timeline. It is automatically called by the
	/// system whenever an update to a registry occurs, capturing the type of
	/// activity and the precise time at which it happened. This automated
	/// tracking is crucial for maintaining a consistent and auditable record of
	/// all registry-related activities.
	// NOTE: 'tx_id' is the registry id on which the particular action was done on. 
	// 		 'tx_type': there are multiple identifiers for the entire Cord system(eg. Registries, Entries, Schemas, etc.)
	// 		 'tx_action' is the type of action done(Authorization, Revoke, Reinstate, etc)
	pub fn update_activity(
		tx_id: &RegistryIdOf,
		tx_type: IdentifierTypeOf,
		tx_action: CallTypeOf,
	) -> Result<(), Error<T>> {
		let tx_moment = Self::timepoint();

		let tx_entry = EventEntryOf { action: tx_action, location: tx_moment };
		let _ = IdentifierTimeline::update_timeline::<T>(tx_id, tx_type, tx_entry);
		Ok(())
	}

	/// Retrieves the current timepoint.
	///
	/// This function returns a Timepoint structure containing the current
	/// block number and extrinsic index. It is typically used in conjunction
	/// with update_activity to record when an event occurred.
	pub fn timepoint() -> Timepoint {
		Timepoint {
			// NOTE: this is the height of the block at the present time in the blockchain. Useful for future indexing.
			height: frame_system::Pallet::<T>::block_number().unique_saturated_into(),
			// NOTE: this is the index of the extrinsic(transaction) in the block.
			// eg. BLOCK -> [EXTRINSIC1, EXTRINSIC2, EXTRINSIC3, EXTRINSIC4, ...]
			//     If our tx is EXTRINSIC2, then index = 2
			index: frame_system::Pallet::<T>::extrinsic_index().unwrap_or_default(),
		}
	}

	/// Method to check if the input identifier calculated from sdk
	/// is actually a valid SS58 Identifier Format and of valid type Registries.
	pub fn is_valid_ss58_format(identifier: &Ss58Identifier) -> bool {
		match identifier.get_type() {
			Ok(id_type) =>
				if id_type == IdentifierType::Registries {
					log::debug!("The SS58 identifier is of type Registries.");
					true
				} else {
					log::debug!("The SS58 identifier is not of type Registries.");
					false
				},
			Err(e) => {
				log::debug!("Invalid SS58 identifier. Error: {:?}", e);
				false
			},
		}
	}
}