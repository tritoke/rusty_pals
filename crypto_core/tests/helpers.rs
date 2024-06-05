#![allow(unused)]

macro_rules! impl_error_boilerplate {
    ($error_type:ty) => {
        impl std::fmt::Display for $error_type {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{self:?}")
            }
        }

        impl std::error::Error for $error_type {}
    };
}

macro_rules! impl_error_from_type {
    ($error_type:ty: $type:ty => $member:ident) => {
        impl From<$type> for ChallengeError {
            fn from(value: $type) -> Self {
                Self::$member(value)
            }
        }
    };
}

macro_rules! impl_error_from_types {
    ($error_type:ty: $($type:tt),+) => {
        $(
            impl_error_from_type!($error_type: $type => $type);
        )*
    };
}

pub(crate) use impl_error_boilerplate;
pub(crate) use impl_error_from_type;
pub(crate) use impl_error_from_types;
