pub use std::sync::Arc;
pub use vulkano::{
    buffer::Subbuffer,
    buffer::{Buffer, BufferCreateInfo, BufferUsage},
    command_buffer::allocator::StandardCommandBufferAllocator,
    command_buffer::{AutoCommandBufferBuilder, CommandBufferUsage, CopyBufferInfo, PrimaryCommandBufferAbstract},
    descriptor_set::{allocator::StandardDescriptorSetAllocator, DescriptorSet, WriteDescriptorSet},
    device::{physical::PhysicalDeviceType, DeviceCreateInfo, DeviceExtensions, QueueCreateInfo, QueueFlags},
    device::{Device, Queue},
    instance::{Instance, InstanceCreateFlags, InstanceCreateInfo},
    memory::allocator::StandardMemoryAllocator,
    memory::allocator::{AllocationCreateInfo, MemoryTypeFilter},
    pipeline::{
        compute::ComputePipelineCreateInfo, layout::PipelineDescriptorSetLayoutCreateInfo, ComputePipeline, Pipeline, PipelineBindPoint, PipelineLayout,
        PipelineShaderStageCreateInfo,
    },
    sync::GpuFuture,
    VulkanLibrary,
};

use super::{mat_transpose_shader, mat_x_mat_shader};
use crate::ChalametPIRError;
use chalametpir_common::matrix::Matrix;

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

pub fn transfer_mat_to_device(
    queue: Arc<Queue>,
    mem_alloc: Arc<StandardMemoryAllocator>,
    cmd_buf_alloc: Arc<StandardCommandBufferAllocator>,
    matrix: Matrix,
) -> Result<Subbuffer<[u8]>, ChalametPIRError> {
    let matrix_as_bytes = matrix.to_bytes();
    let matrix_byte_len = matrix_as_bytes.len() as u64;

    let src_buf = Buffer::from_iter(
        mem_alloc.clone(),
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
    .map_err(|_| ChalametPIRError::VulkanBufferCreationFailed)?;

    let dst_buf = Buffer::new_slice::<u8>(
        mem_alloc.clone(),
        BufferCreateInfo {
            usage: BufferUsage::STORAGE_BUFFER | BufferUsage::TRANSFER_DST,
            ..Default::default()
        },
        AllocationCreateInfo {
            memory_type_filter: MemoryTypeFilter::PREFER_DEVICE,
            ..Default::default()
        },
        matrix_byte_len,
    )
    .map_err(|_| ChalametPIRError::VulkanBufferCreationFailed)?;

    let cmd_buf = {
        let mut builder = AutoCommandBufferBuilder::primary(cmd_buf_alloc, queue.queue_family_index(), CommandBufferUsage::OneTimeSubmit)
            .map_err(|_| ChalametPIRError::VulkanCommandBufferBuilderCreationFailed)?;

        builder
            .copy_buffer(CopyBufferInfo::buffers(src_buf, dst_buf.clone()))
            .map_err(|_| ChalametPIRError::VulkanCommandBufferRecordingFailed)?;

        builder.build().map_err(|_| ChalametPIRError::VulkanCommandBufferBuildingFailed)?
    };

    cmd_buf
        .execute(queue)
        .map_err(|_| ChalametPIRError::VulkanCommandBufferExecutionFailed)?
        .then_signal_fence_and_flush()
        .map_err(|_| ChalametPIRError::VulkanCommandBufferExecutionFailed)?
        .wait(None)
        .map_err(|_| ChalametPIRError::VulkanCommandBufferExecutionFailed)?;

    Ok(dst_buf)
}

pub fn get_empty_host_readable_buffer(memory_allocator: Arc<StandardMemoryAllocator>, byte_len: u64) -> Result<Subbuffer<[u8]>, ChalametPIRError> {
    Buffer::new_slice::<u8>(
        memory_allocator.clone(),
        BufferCreateInfo {
            usage: BufferUsage::STORAGE_BUFFER,
            ..Default::default()
        },
        AllocationCreateInfo {
            memory_type_filter: MemoryTypeFilter::HOST_SEQUENTIAL_WRITE | MemoryTypeFilter::PREFER_DEVICE,
            ..Default::default()
        },
        byte_len,
    )
    .map_err(|_| ChalametPIRError::VulkanBufferCreationFailed)
}

pub fn mat_x_mat(
    device: Arc<Device>,
    queue: Arc<Queue>,
    command_buffer_allocator: Arc<StandardCommandBufferAllocator>,
    left_mat: Subbuffer<[u8]>,
    rhs_mat: Subbuffer<[u8]>,
    res_mat: Subbuffer<[u8]>,
    wg_count: [u32; 3],
) -> Result<(), ChalametPIRError> {
    let pipeline = {
        let cs = mat_x_mat_shader::load(device.clone()).map_err(|_| ChalametPIRError::VulkanComputeShaderLoadingFailed)?;
        let cs_entry_point = cs.entry_point("main").ok_or(ChalametPIRError::VulkanComputeShaderLoadingFailed)?;
        let compute_stage = PipelineShaderStageCreateInfo::new(cs_entry_point);

        let layout = PipelineLayout::new(
            device.clone(),
            PipelineDescriptorSetLayoutCreateInfo::from_stages([&compute_stage])
                .into_pipeline_layout_create_info(device.clone())
                .map_err(|_| ChalametPIRError::VulkanComputePipelineCreationFailed)?,
        )
        .map_err(|_| ChalametPIRError::VulkanComputePipelineCreationFailed)?;

        ComputePipeline::new(device.clone(), None, ComputePipelineCreateInfo::stage_layout(compute_stage, layout.clone()))
            .map_err(|_| ChalametPIRError::VulkanComputePipelineCreationFailed)?
    };

    let descriptor_set_allocator = Arc::new(StandardDescriptorSetAllocator::new(device.clone(), Default::default()));
    let descriptor_set_layout = pipeline.layout().set_layouts()[0].clone();
    let descriptor_set = DescriptorSet::new(
        descriptor_set_allocator,
        descriptor_set_layout,
        [
            WriteDescriptorSet::buffer(0, left_mat),
            WriteDescriptorSet::buffer(1, rhs_mat),
            WriteDescriptorSet::buffer(2, res_mat),
        ],
        [],
    )
    .map_err(|_| ChalametPIRError::VulkanDescriptorSetCreationFailed)?;

    let command_buffer = {
        let mut command_buffer_builder = AutoCommandBufferBuilder::primary(command_buffer_allocator, queue.queue_family_index(), CommandBufferUsage::OneTimeSubmit)
            .map_err(|_| ChalametPIRError::VulkanCommandBufferBuilderCreationFailed)?;

        unsafe {
            command_buffer_builder
                .bind_pipeline_compute(pipeline.clone())
                .map_err(|_| ChalametPIRError::VulkanCommandBufferRecordingFailed)?
                .bind_descriptor_sets(PipelineBindPoint::Compute, pipeline.layout().clone(), 0, descriptor_set)
                .map_err(|_| ChalametPIRError::VulkanCommandBufferRecordingFailed)?
                .dispatch(wg_count)
                .map_err(|_| ChalametPIRError::VulkanCommandBufferRecordingFailed)?;
        }

        command_buffer_builder.build().map_err(|_| ChalametPIRError::VulkanCommandBufferBuildingFailed)?
    };

    command_buffer
        .execute(queue.clone())
        .map_err(|_| ChalametPIRError::VulkanCommandBufferExecutionFailed)?
        .then_signal_fence_and_flush()
        .map_err(|_| ChalametPIRError::VulkanCommandBufferExecutionFailed)?
        .wait(None)
        .map_err(|_| ChalametPIRError::VulkanCommandBufferExecutionFailed)
}

pub fn mat_transpose(
    device: Arc<Device>,
    queue: Arc<Queue>,
    command_buffer_allocator: Arc<StandardCommandBufferAllocator>,
    orig_mat: Subbuffer<[u8]>,
    res_mat: Subbuffer<[u8]>,
    wg_count: [u32; 3],
) -> Result<(), ChalametPIRError> {
    let pipeline = {
        let cs = mat_transpose_shader::load(device.clone()).map_err(|_| ChalametPIRError::VulkanComputeShaderLoadingFailed)?;
        let cs_entry_point = cs.entry_point("main").ok_or(ChalametPIRError::VulkanComputeShaderLoadingFailed)?;
        let compute_stage = PipelineShaderStageCreateInfo::new(cs_entry_point);

        let layout = PipelineLayout::new(
            device.clone(),
            PipelineDescriptorSetLayoutCreateInfo::from_stages([&compute_stage])
                .into_pipeline_layout_create_info(device.clone())
                .map_err(|_| ChalametPIRError::VulkanComputePipelineCreationFailed)?,
        )
        .map_err(|_| ChalametPIRError::VulkanComputePipelineCreationFailed)?;

        ComputePipeline::new(device.clone(), None, ComputePipelineCreateInfo::stage_layout(compute_stage, layout.clone()))
            .map_err(|_| ChalametPIRError::VulkanComputePipelineCreationFailed)?
    };

    let descriptor_set_allocator = Arc::new(StandardDescriptorSetAllocator::new(device.clone(), Default::default()));
    let descriptor_set_layout = pipeline.layout().set_layouts()[0].clone();
    let descriptor_set = DescriptorSet::new(
        descriptor_set_allocator,
        descriptor_set_layout,
        [WriteDescriptorSet::buffer(0, orig_mat), WriteDescriptorSet::buffer(1, res_mat)],
        [],
    )
    .map_err(|_| ChalametPIRError::VulkanDescriptorSetCreationFailed)?;

    let command_buffer = {
        let mut command_buffer_builder = AutoCommandBufferBuilder::primary(command_buffer_allocator, queue.queue_family_index(), CommandBufferUsage::OneTimeSubmit)
            .map_err(|_| ChalametPIRError::VulkanCommandBufferBuilderCreationFailed)?;

        unsafe {
            command_buffer_builder
                .bind_pipeline_compute(pipeline.clone())
                .map_err(|_| ChalametPIRError::VulkanCommandBufferRecordingFailed)?
                .bind_descriptor_sets(PipelineBindPoint::Compute, pipeline.layout().clone(), 0, descriptor_set)
                .map_err(|_| ChalametPIRError::VulkanCommandBufferRecordingFailed)?
                .dispatch(wg_count)
                .map_err(|_| ChalametPIRError::VulkanCommandBufferRecordingFailed)?;
        }

        command_buffer_builder.build().map_err(|_| ChalametPIRError::VulkanCommandBufferBuildingFailed)?
    };

    command_buffer
        .execute(queue.clone())
        .map_err(|_| ChalametPIRError::VulkanCommandBufferExecutionFailed)?
        .then_signal_fence_and_flush()
        .map_err(|_| ChalametPIRError::VulkanCommandBufferExecutionFailed)?
        .wait(None)
        .map_err(|_| ChalametPIRError::VulkanCommandBufferExecutionFailed)
}
