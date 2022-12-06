#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    constraint::SanitizedMediaTrackConstraint, MediaTrackConstraint,
    MediaTrackSupportedConstraints, ResolvedMediaTrackConstraint,
};

use super::{
    advanced::GenericAdvancedMediaTrackConstraints, constraint_set::GenericMediaTrackConstraintSet,
    mandatory::GenericMandatoryMediaTrackConstraints,
};

/// A boolean on/off flag or bare value or constraints for a [`MediaStreamTrack`][media_stream_track] object.
pub type BoolOrMediaTrackConstraints = GenericBoolOrMediaTrackConstraints<MediaTrackConstraint>;

/// A boolean on/off flag or constraints for a [`MediaStreamTrack`][media_stream_track] object.
pub type BoolOrResolvedMediaTrackConstraints =
    GenericBoolOrMediaTrackConstraints<ResolvedMediaTrackConstraint>;

/// A boolean on/off flag or constraints for a [`MediaStreamTrack`][media_stream_track] object.
///
/// # W3C Spec Compliance
///
/// There exists no direct corresponding type in the
/// W3C ["Media Capture and Streams"][media_capture_and_streams_spec] spec,
/// since the `BoolOrMediaTrackConstraints<T>` type aims to be a
/// generalization over multiple types in the W3C spec:
///
/// | Rust                          | W3C                                                                                                |
/// | ----------------------------- | -------------------------------------------------------------------------------------------------- |
/// | `BoolOrMediaTrackConstraints` | [`ResolvedMediaStreamConstraints`][media_stream_constraints]'s [`video`][video] / [`audio`][audio] members |
///
/// [media_stream_constraints]: https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamconstraints-video
/// [media_stream_track]: https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack
/// [video]: https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamconstraints-video
/// [audio]: https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamconstraints-audio
/// [media_capture_and_streams_spec]: https://www.w3.org/TR/mediacapture-streams/
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
pub enum GenericBoolOrMediaTrackConstraints<T> {
    /// Boolean track selector.
    Bool(bool),
    /// Constraints-based track selector.
    Constraints(GenericMediaTrackConstraints<T>),
}

impl<T> GenericBoolOrMediaTrackConstraints<T>
where
    T: Clone,
{
    pub fn to_constraints(&self) -> Option<GenericMediaTrackConstraints<T>> {
        self.clone().into_constraints()
    }

    pub fn into_constraints(self) -> Option<GenericMediaTrackConstraints<T>> {
        match self {
            Self::Bool(false) => None,
            Self::Bool(true) => Some(GenericMediaTrackConstraints::default()),
            Self::Constraints(constraints) => Some(constraints),
        }
    }
}

impl<T> Default for GenericBoolOrMediaTrackConstraints<T> {
    fn default() -> Self {
        Self::Bool(false)
    }
}

impl<T> From<bool> for GenericBoolOrMediaTrackConstraints<T> {
    fn from(flag: bool) -> Self {
        Self::Bool(flag)
    }
}

impl<T> From<GenericMediaTrackConstraints<T>> for GenericBoolOrMediaTrackConstraints<T> {
    fn from(constraints: GenericMediaTrackConstraints<T>) -> Self {
        Self::Constraints(constraints)
    }
}

impl BoolOrMediaTrackConstraints {
    pub fn to_resolved(&self) -> BoolOrResolvedMediaTrackConstraints {
        self.clone().into_resolved()
    }

    pub fn into_resolved(self) -> BoolOrResolvedMediaTrackConstraints {
        match self {
            Self::Bool(flag) => BoolOrResolvedMediaTrackConstraints::Bool(flag),
            Self::Constraints(constraints) => {
                BoolOrResolvedMediaTrackConstraints::Constraints(constraints.into_resolved())
            }
        }
    }
}

/// Media track constraints that contains either bare values or constraints.
pub type MediaTrackConstraints = GenericMediaTrackConstraints<MediaTrackConstraint>;

/// Media track constraints that contains only constraints (both, empty and non-empty).
pub type ResolvedMediaTrackConstraints = GenericMediaTrackConstraints<ResolvedMediaTrackConstraint>;

/// Media track constraints that contains only non-empty constraints.
pub type SanitizedMediaTrackConstraints =
    GenericMediaTrackConstraints<SanitizedMediaTrackConstraint>;

/// The constraints for a [`MediaStreamTrack`][media_stream_track] object.
///
/// # W3C Spec Compliance
///
/// Corresponds to [`MediaTrackConstraints`][media_track_constraints]
/// from the W3C ["Media Capture and Streams"][media_capture_and_streams_spec] spec.
///
/// [media_stream_track]: https://www.w3.org/TR/mediacapture-streams/#dom-mediastreamtrack
/// [media_track_constraints]: https://www.w3.org/TR/mediacapture-streams/#dom-mediatrackconstraints
/// [media_capture_and_streams_spec]: https://www.w3.org/TR/mediacapture-streams/
#[derive(Debug, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct GenericMediaTrackConstraints<T> {
    /// Mandatory (i.e required or optional basic) constraints, as defined in the [spec][spec].
    ///
    /// [spec]: https://www.w3.org/TR/mediacapture-streams/#dfn-constraint
    #[cfg_attr(feature = "serde", serde(flatten))]
    pub mandatory: GenericMandatoryMediaTrackConstraints<T>,

    /// Advanced constraints, as defined in the [spec][spec].
    ///
    /// [spec]: https://www.w3.org/TR/mediacapture-streams/#dfn-constraint
    #[cfg_attr(
        feature = "serde",
        serde(default = "Default::default"),
        serde(skip_serializing_if = "should_skip_advanced")
    )]
    pub advanced: GenericAdvancedMediaTrackConstraints<T>,
}

#[cfg(feature = "serde")]
fn should_skip_advanced<T>(advanced: &GenericAdvancedMediaTrackConstraints<T>) -> bool {
    advanced.is_empty()
}

impl<T> GenericMediaTrackConstraints<T> {
    pub fn new(
        mandatory: GenericMandatoryMediaTrackConstraints<T>,
        advanced: GenericAdvancedMediaTrackConstraints<T>,
    ) -> Self {
        Self {
            mandatory,
            advanced,
        }
    }
}

impl GenericMediaTrackConstraints<ResolvedMediaTrackConstraint> {
    pub fn basic(&self) -> GenericMediaTrackConstraintSet<ResolvedMediaTrackConstraint> {
        self.basic_or_required(false)
    }

    pub fn required(&self) -> GenericMediaTrackConstraintSet<ResolvedMediaTrackConstraint> {
        self.basic_or_required(true)
    }

    fn basic_or_required(
        &self,
        required: bool,
    ) -> GenericMediaTrackConstraintSet<ResolvedMediaTrackConstraint> {
        GenericMediaTrackConstraintSet::new(
            self.mandatory
                .iter()
                .filter_map(|(property, constraint)| {
                    if constraint.is_required() == required {
                        Some((property.clone(), constraint.clone()))
                    } else {
                        None
                    }
                })
                .collect(),
        )
    }
}

impl<T> Default for GenericMediaTrackConstraints<T> {
    fn default() -> Self {
        Self {
            mandatory: Default::default(),
            advanced: Default::default(),
        }
    }
}

impl From<MediaTrackConstraints> for ResolvedMediaTrackConstraints {
    fn from(constraints: MediaTrackConstraints) -> Self {
        constraints.into_resolved()
    }
}

impl MediaTrackConstraints {
    pub fn to_resolved(&self) -> ResolvedMediaTrackConstraints {
        self.clone().into_resolved()
    }

    pub fn into_resolved(self) -> ResolvedMediaTrackConstraints {
        let Self {
            mandatory,
            advanced,
        } = self;
        ResolvedMediaTrackConstraints {
            mandatory: mandatory.into_resolved(),
            advanced: advanced.into_resolved(),
        }
    }
}

impl ResolvedMediaTrackConstraints {
    pub fn to_sanitized(
        &self,
        supported_constraints: &MediaTrackSupportedConstraints,
    ) -> SanitizedMediaTrackConstraints {
        self.clone().into_sanitized(supported_constraints)
    }

    pub fn into_sanitized(
        self,
        supported_constraints: &MediaTrackSupportedConstraints,
    ) -> SanitizedMediaTrackConstraints {
        let mandatory = self.mandatory.into_sanitized(supported_constraints);
        let advanced = self.advanced.into_sanitized(supported_constraints);
        SanitizedMediaTrackConstraints {
            mandatory,
            advanced,
        }
    }
}

#[cfg(feature = "serde")]
#[cfg(test)]
mod serde_tests {
    use std::iter::FromIterator;

    use crate::{
        constraints::mandatory::MandatoryMediaTrackConstraints, macros::test_serde_symmetry,
        property::all::name::*, AdvancedMediaTrackConstraints, MediaTrackConstraintSet,
    };

    use super::*;

    type Subject = MediaTrackConstraints;

    #[test]
    fn default() {
        let subject = Subject::default();
        let json = serde_json::json!({});

        test_serde_symmetry!(subject: subject, json: json);
    }

    #[test]
    fn customized() {
        let subject = Subject {
            mandatory: MandatoryMediaTrackConstraints::from_iter([(
                DEVICE_ID,
                "microphone".into(),
            )]),
            advanced: AdvancedMediaTrackConstraints::new(vec![
                MediaTrackConstraintSet::from_iter([
                    (AUTO_GAIN_CONTROL, true.into()),
                    (CHANNEL_COUNT, 2.into()),
                ]),
                MediaTrackConstraintSet::from_iter([(LATENCY, 0.123.into())]),
            ]),
        };
        let json = serde_json::json!({
            "deviceId": "microphone",
            "advanced": [
                {
                    "autoGainControl": true,
                    "channelCount": 2,
                },
                {
                    "latency": 0.123,
                },
            ]
        });

        test_serde_symmetry!(subject: subject, json: json);
    }
}