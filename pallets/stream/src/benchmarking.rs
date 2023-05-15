#![cfg(feature = "runtime-benchmarks")]

use super::*;
use codec::Encode;
use cord_primitives::curi::Ss58Identifier;
use cord_utilities::traits::GenerateBenchmarkOrigin;
use frame_benchmarking::{account, benchmarks, impl_benchmark_test_suite};
use frame_support::{pallet_prelude::*, sp_runtime::traits::Hash};
use pallet_registry::{
	Authorizations, InputRegistryOf, Permissions, RegistryAuthorizationOf, RegistryHashOf,
};
use pallet_schema::SchemaHashOf;
use sp_std::{
	convert::{TryFrom, TryInto},
	vec::Vec,
};

const SEED: u32 = 0;
const MAX_PAYLOAD_BYTE_LENGTH: u32 = 5 * 1024;

pub fn generate_stream_id<T: Config>(digest: &StreamHashOf<T>) -> StreamIdOf {
	Ss58Identifier::to_stream_id(&(digest).encode()[..]).unwrap()
}

pub fn generate_schema_id<T: Config>(digest: &SchemaHashOf<T>) -> SchemaIdOf {
	Ss58Identifier::to_schema_id(&(digest).encode()[..]).unwrap()
}

pub fn generate_registry_id<T: Config>(digest: &RegistryHashOf<T>) -> RegistryIdOf {
	Ss58Identifier::to_registry_id(&(digest).encode()[..]).unwrap()
}

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
	frame_system::Pallet::<T>::assert_last_event(generic_event.into());
}

benchmarks! {
	where_clause {
		where
		<T as Config>::EnsureOrigin: GenerateBenchmarkOrigin<T::RuntimeOrigin, T::AccountId, T::RegistryCreatorId>,
		}
	create {
		let l in 1 .. MAX_PAYLOAD_BYTE_LENGTH;

		let caller: T::AccountId = account("caller", 0, SEED);
		let did: T::RegistryCreatorId = account("did", 0, SEED);
		let did1: T::RegistryCreatorId = account("did1", 0, SEED);

		let stream = vec![77u8; 32];

		let stream_digest = <T as frame_system::Config>::Hashing::hash(&stream[..]);

		let raw_registry = [56u8; 256].to_vec();

		let registry: InputRegistryOf<T> = BoundedVec::try_from(raw_registry).unwrap();

		let id_digest = <T as frame_system::Config>::Hashing::hash(
		&[&registry.encode()[..], &did.encode()[..]].concat()[..],
		);

		let registry_id: RegistryIdOf = generate_registry_id::<T>(&id_digest);

		let id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&stream_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]]
				.concat()[..],
		);

		let identifier = Ss58Identifier::to_stream_id(&(id_digest).encode()[..]).unwrap();

		let auth_digest = <T as frame_system::Config>::Hashing::hash(
			&[&registry_id.encode()[..], &did1.encode()[..], &did.encode()[..]].concat()[..],
		);

		let authorization_id: Ss58Identifier =
		Ss58Identifier::to_authorization_id(&auth_digest.encode()[..]).unwrap();

		<Authorizations<T>>::insert(
			&authorization_id,
			RegistryAuthorizationOf::<T> {
				registry_id: registry_id.clone(),
				delegate: did.clone(),
				schema: None,
				permissions: Permissions::all(),
			},
		);

		let origin =  <T as Config>::EnsureOrigin::generate_origin(caller.clone(), did.clone());

	}: _<T::RuntimeOrigin>(origin, stream_digest, authorization_id, None)
	verify {
		assert_last_event::<T>(Event::Create { identifier,digest: stream_digest, author: did}.into());
	}

	update {
		let l in 1 .. MAX_PAYLOAD_BYTE_LENGTH;

		let caller: T::AccountId = account("caller", 0, SEED);
		let did: T::RegistryCreatorId = account("did", 0, SEED);
		let did1: T::RegistryCreatorId = account("did1", 0, SEED);


		let raw_registry = [56u8; 256].to_vec();

		let registry: InputRegistryOf<T> = BoundedVec::try_from(raw_registry).unwrap();

		let id_digest = <T as frame_system::Config>::Hashing::hash(
		&[&registry.encode()[..], &did.encode()[..]].concat()[..],
		);

		let registry_id: RegistryIdOf = generate_registry_id::<T>(&id_digest);

		let stream = vec![77u8; 32];

		let stream_digest = <T as frame_system::Config>::Hashing::hash(&stream[..]);

		let stream_id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&stream_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]].concat()[..],
		);

		let stream_id = generate_stream_id::<T>(&stream_id_digest);

		let id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&stream_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]]
				.concat()[..],
		);

		let identifier = Ss58Identifier::to_stream_id(&(id_digest).encode()[..]).unwrap();

		let auth_digest = <T as frame_system::Config>::Hashing::hash(
			&[&registry_id.encode()[..], &did1.encode()[..], &did.encode()[..]].concat()[..],
		);

		let authorization_id: Ss58Identifier =
		Ss58Identifier::to_authorization_id(&auth_digest.encode()[..]).unwrap();

		<Authorizations<T>>::insert(
			&authorization_id,
			RegistryAuthorizationOf::<T> {
				registry_id: registry_id.clone(),
				delegate: did1.clone(),
				schema: None,
				permissions: Permissions::all(),
			},
		);

		<Streams<T>>::insert(
			&stream_id,
			StreamEntryOf::<T> {
				digest: stream_digest.clone(),
				creator: did.clone(),
				schema: None,
				registry: registry_id.clone(),
				revoked: false,
			},
		);

		let stream_update = vec![12u8; 32];
		let update_digest = <T as frame_system::Config>::Hashing::hash(&stream_update[..]);

		let origin =  <T as Config>::EnsureOrigin::generate_origin(caller.clone(), did.clone());


	}: _<T::RuntimeOrigin>(origin, stream_id, update_digest, authorization_id)
	verify {
		assert_last_event::<T>(Event::Update { identifier,digest: update_digest, author: did}.into());
	}

	revoke {
		let l in 1 .. MAX_PAYLOAD_BYTE_LENGTH;

		let caller: T::AccountId = account("caller", 0, SEED);
		let did: T::RegistryCreatorId = account("did", 0, SEED);
		let did1: T::RegistryCreatorId = account("did1", 0, SEED);


		let raw_registry = [56u8; 256].to_vec();

		let registry: InputRegistryOf<T> = BoundedVec::try_from(raw_registry).unwrap();

		let id_digest = <T as frame_system::Config>::Hashing::hash(
		&[&registry.encode()[..], &did.encode()[..]].concat()[..],
		);

		let registry_id: RegistryIdOf = generate_registry_id::<T>(&id_digest);

		let stream = vec![77u8; 32];

		let stream_digest = <T as frame_system::Config>::Hashing::hash(&stream[..]);

		let stream_id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&stream_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]].concat()[..],
		);

		let stream_id = generate_stream_id::<T>(&stream_id_digest);

		let id_digest = <T as frame_system::Config>::Hashing::hash(
			&[&stream_digest.encode()[..], &registry_id.encode()[..], &did.encode()[..]]
				.concat()[..],
		);

		let identifier = Ss58Identifier::to_stream_id(&(id_digest).encode()[..]).unwrap();

		let auth_digest = <T as frame_system::Config>::Hashing::hash(
			&[&registry_id.encode()[..], &did1.encode()[..], &did.encode()[..]].concat()[..],
		);

		let authorization_id: Ss58Identifier =
		Ss58Identifier::to_authorization_id(&auth_digest.encode()[..]).unwrap();

		<Authorizations<T>>::insert(
			&authorization_id,
			RegistryAuthorizationOf::<T> {
				registry_id: registry_id.clone(),
				delegate: did1.clone(),
				schema: None,
				permissions: Permissions::all(),
			},
		);

		<Streams<T>>::insert(
			&stream_id,
			StreamEntryOf::<T> {
				digest: stream_digest.clone(),
				creator: did.clone(),
				schema: None,
				registry: registry_id.clone(),
				revoked: false,
			},
		);


		let origin =  <T as Config>::EnsureOrigin::generate_origin(caller.clone(), did.clone());


	}: _<T::RuntimeOrigin>(origin, stream_id.clone(), authorization_id)
	verify {
		assert_last_event::<T>(Event::Revoke { identifier:stream_id,author: did}.into());
	}
}

impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);