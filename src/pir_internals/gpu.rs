use super::matrix::Matrix;
use crate::ChalametPIRError;
use std::sync::Arc;
use vulkano::{
    VulkanLibrary,
    buffer::{Buffer, BufferCreateInfo, BufferUsage, Subbuffer},
    command_buffer::{
        AutoCommandBufferBuilder, CopyBufferInfo, PrimaryAutoCommandBuffer, PrimaryCommandBufferAbstract, allocator::StandardCommandBufferAllocator,
    },
    device::{Device, DeviceCreateInfo, DeviceExtensions, Queue, QueueCreateInfo, QueueFlags, physical::PhysicalDeviceType},
    instance::{Instance, InstanceCreateFlags, InstanceCreateInfo},
    memory::allocator::{AllocationCreateInfo, MemoryTypeFilter, StandardMemoryAllocator},
    sync::GpuFuture,
};

pub fn setup_gpu() -> Result<(Arc<Device>, Arc<Queue>, Arc<StandardMemoryAllocator>, Arc<StandardCommandBufferAllocator>), ChalametPIRError> {
    let library = VulkanLibrary::new().map_err(|_| ChalametPIRError::VulkanLibraryNotFound)?;
    let instance = Instance::new(
        library,
        InstanceCreateInfo {
            flags: InstanceCreateFlags::ENUMERATE_PORTABILITY,
            ..Default::default()
        },
    )
    .map_err(|_| ChalametPIRError::VulkanInstanceCreationFailed)?;

    let device_extensions = DeviceExtensions {
        khr_storage_buffer_storage_class: true,
        ..DeviceExtensions::empty()
    };

    let (physical_device, queue_family_index) = instance
        .enumerate_physical_devices()
        .map_err(|_| ChalametPIRError::VulkanPhysicalDeviceNotFound)?
        .filter(|p| p.supported_extensions().contains(&device_extensions))
        .filter_map(|p| {
            p.queue_family_properties()
                .iter()
                .position(|q| q.queue_flags.intersects(QueueFlags::COMPUTE | QueueFlags::TRANSFER))
                .map(|i| (p, i as u32))
        })
        .min_by_key(|(p, _)| match p.properties().device_type {
            PhysicalDeviceType::DiscreteGpu => 0,
            PhysicalDeviceType::IntegratedGpu => 1,
            PhysicalDeviceType::VirtualGpu => 2,
            PhysicalDeviceType::Cpu => 3,
            PhysicalDeviceType::Other => 4,
            _ => 5,
        })
        .ok_or(ChalametPIRError::VulkanPhysicalDeviceNotFound)?;

    let (device, mut queues) = Device::new(
        physical_device,
        DeviceCreateInfo {
            enabled_extensions: device_extensions,
            queue_create_infos: vec![QueueCreateInfo {
                queue_family_index,
                ..Default::default()
            }],
            ..Default::default()
        },
    )
    .map_err(|_| ChalametPIRError::VulkanDeviceCreationFailed)?;
    let queue = queues.next().ok_or(ChalametPIRError::VulkanDeviceCreationFailed)?;

    let memory_allocator = Arc::new(StandardMemoryAllocator::new_default(device.clone()));
    let command_buffer_allocator = Arc::new(StandardCommandBufferAllocator::new(device.clone(), Default::default()));

    Ok((device, queue, memory_allocator, command_buffer_allocator))
}

pub fn matrix_to_src_buffer(memory_allocator: Arc<StandardMemoryAllocator>, matrix: Matrix) -> Result<Subbuffer<[u8]>, ChalametPIRError> {
    let matrix_as_bytes = matrix.to_bytes();
    Buffer::from_iter(
        memory_allocator.clone(),
        BufferCreateInfo {
            usage: BufferUsage::TRANSFER_SRC,
            ..Default::default()
        },
        AllocationCreateInfo {
            memory_type_filter: MemoryTypeFilter::HOST_SEQUENTIAL_WRITE | MemoryTypeFilter::PREFER_DEVICE,
            ..Default::default()
        },
        matrix_as_bytes,
    )
    .map_err(|_| ChalametPIRError::VulkanSourceBufferCreationFailed)
}

pub fn get_empty_storage_buffer(memory_allocator: Arc<StandardMemoryAllocator>, byte_len: u64) -> Result<Subbuffer<[u8]>, ChalametPIRError> {
    Buffer::new_slice::<u8>(
        memory_allocator.clone(),
        BufferCreateInfo {
            usage: BufferUsage::STORAGE_BUFFER | BufferUsage::TRANSFER_DST,
            ..Default::default()
        },
        AllocationCreateInfo {
            memory_type_filter: MemoryTypeFilter::PREFER_DEVICE,
            ..Default::default()
        },
        byte_len,
    )
    .map_err(|_| ChalametPIRError::VulkanEmptyBufferCreationFailed)
}

pub fn record_transfer(
    cmd_buf_builder: &mut AutoCommandBufferBuilder<PrimaryAutoCommandBuffer>,
    src: Subbuffer<[u8]>,
    dst: Subbuffer<[u8]>,
) -> Result<&mut AutoCommandBufferBuilder<PrimaryAutoCommandBuffer>, ChalametPIRError> {
    cmd_buf_builder
        .copy_buffer(CopyBufferInfo::buffers(src, dst))
        .map_err(|_| ChalametPIRError::VulkanTransferCommandRecordFailed)
}

pub fn finish_transfer(cmd_buf_builder: AutoCommandBufferBuilder<PrimaryAutoCommandBuffer>, queue: Arc<Queue>) -> Result<(), ChalametPIRError> {
    cmd_buf_builder
        .build()
        .map_err(|_| ChalametPIRError::VulkanCommandBufferBuildingFailed)?
        .execute(queue.clone())
        .map_err(|_| ChalametPIRError::VulkanCommandBufferExecutionFailed)?
        .then_signal_fence_and_flush()
        .map_err(|_| ChalametPIRError::VulkanCommandBufferExecutionFailed)?
        .wait(None)
        .map_err(|_| ChalametPIRError::VulkanCommandBufferExecutionFailed)
}
